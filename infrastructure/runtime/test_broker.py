import base64
import copy
import io
import unittest
from unittest.mock import patch
import broker
from broker import Broker


class Table:
    def __init__(self):
        self.items = {}
        self.fail = False

    def get_item(self, Key, ConsistentRead):
        assert ConsistentRead
        return {"Item": copy.deepcopy(self.items.get(Key["id"], {}))}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, ExpressionAttributeNames=None, ConditionExpression=None):
        if self.fail:
            raise RuntimeError("state unavailable")
        item = self.items.setdefault(Key["id"], {})
        if ConditionExpression == "attribute_not_exists(lease_until) OR lease_until < :now":
            if item.get("lease_until", -1) >= ExpressionAttributeValues[":now"]:
                raise RuntimeError("locked")
            item.update({"lease_until": ExpressionAttributeValues[":lease"], "lock_owner": ExpressionAttributeValues[":owner"]})
        elif ConditionExpression == "lock_owner = :owner":
            if item.get("lock_owner") != ExpressionAttributeValues[":owner"]:
                raise RuntimeError("not owner")
            item["lease_until"] = ExpressionAttributeValues[":released"]
        else:
            item.update({v: True for v in ExpressionAttributeNames.values()})

    def put_item(self, Item, **kwargs):
        if self.fail:
            raise RuntimeError("state unavailable")
        if kwargs.get("ConditionExpression") and Item["id"] in self.items:
            raise RuntimeError("reserved")
        self.items[Item["id"]] = copy.deepcopy(Item)


class S3:
    def __init__(self):
        self.objects = {"seeds/honey.csv": b"honey", "seeds/critical.csv": b"important"}
        self.tags = {}
        self.fail_write = False

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self.objects[Key])}

    def put_object(self, Bucket, Key, Body, Tagging):
        if self.fail_write:
            raise RuntimeError("S3 unavailable")
        self.objects[Key], self.tags[Key] = Body, Tagging


class STS:
    def __init__(self):
        self.count = 0

    def assume_role(self, **kwargs):
        self.count += 1
        return {"Credentials": {"AccessKeyId": f"key-{self.count}", "SecretAccessKey": "secret",
                                 "SessionToken": "token", "Expiration": "future"}}


class Tests(unittest.TestCase):
    def setUp(self):
        self.table, self.s3, self.sts = Table(), S3(), STS()
        self.table.items["mine:s3:bucket/seeds/honey.csv"] = {
            "mine_id": "mine-honey", "emit_c_on_read": True, "emit_d": True
        }
        self.table.items["mine:s3:bucket/seeds/critical.csv"] = {
            "mine_id": "mine-critical", "emit_c_on_read": False, "emit_d": True
        }
        self.b = Broker(self.table, self.s3, self.sts, "bucket", "role")

    def test_honey_before_release_and_independent_sessions(self):
        result = self.b.run("a", {"operation": "read", "key": "seeds/honey.csv"})
        self.assertTrue(result["intersection"])
        self.assertTrue(self.b.get("a")["c"])
        self.assertFalse(self.b.effective("other")["c"])

    def test_d_only_read_then_arbitrary_write_conservatively_inherits(self):
        self.b.run("a", {"operation": "read", "key": "seeds/critical.csv"})
        result = self.b.run("a", {"operation": "put", "destination": "derived/transformed", "data": "eA=="})
        self.assertFalse(result["c"])
        self.assertTrue(result["d"])
        self.assertIn("taint-d=true", self.s3.tags["derived/transformed"])

    def test_normal_write_clean(self):
        result = self.b.run("a", {"operation": "put", "destination": "derived/normal", "data": "eA=="})
        self.assertFalse(result["c"] or result["d"])

    def test_registry_policy_is_not_tied_to_seed_filename(self):
        self.s3.objects["custom/canary.bin"] = b"canary"
        self.table.items["mine:s3:bucket/custom/canary.bin"] = {
            "mine_id": "mine-custom", "emit_c_on_read": True, "emit_d": False
        }
        result = self.b.run("a", {"operation": "read", "key": "custom/canary.bin"})
        self.assertTrue(result["c"])
        self.assertFalse(result["d"])

    def test_delegation_and_later_parent_infection(self):
        result = self.b.run("a", {"operation": "delegate"})
        child = self.b.credential(result["credentials"]["AccessKeyId"])
        self.assertFalse(self.b.effective(child)["c"])
        self.b.run("a", {"operation": "read", "key": "seeds/honey.csv"})
        self.assertTrue(self.b.effective(child)["c"])
        self.assertFalse(self.b.effective("separate")["c"])

    def test_copy_lineage_and_tags(self):
        self.b.run("a", {"operation": "read", "key": "seeds/honey.csv"})
        self.b.run("a", {"operation": "copy", "key": "seeds/critical.csv", "destination": "derived/one"})
        result = self.b.run("a", {"operation": "copy", "key": "derived/one", "destination": "derived/two"})
        self.assertTrue(result["intersection"])
        self.assertEqual(self.s3.objects["derived/two"], b"important")

    def test_c_footprint_read_is_not_control_transfer(self):
        self.b.join("a", c=True)
        self.b.run("a", {"operation": "put", "destination": "derived/code", "data": "eA=="})
        self.assertFalse(self.b.run("b", {"operation": "read", "key": "derived/code"})["c"])

    def test_labels_never_clear(self):
        self.b.join("a", c=True, d=True)
        self.b.join("a", c=False, d=False)
        self.assertTrue(self.b.effective("a")["c"] and self.b.effective("a")["d"])

    def test_state_failure_does_not_release_honey(self):
        self.b.resource("seeds/honey.csv")
        self.table.fail = True
        with self.assertRaises(RuntimeError):
            self.b.run("a", {"operation": "read", "key": "seeds/honey.csv"})

    def test_failed_write_preserves_label_and_blocks_overwrite(self):
        self.b.join("a", c=True, d=True)
        self.s3.fail_write = True
        with self.assertRaises(RuntimeError):
            self.b.run("a", {"operation": "put", "destination": "derived/fail", "data": "eA=="})
        self.assertTrue(self.b.get("s3:bucket/derived/fail")["c"])
        self.s3.fail_write = False
        with self.assertRaises(RuntimeError):
            self.b.run("b", {"operation": "put", "destination": "derived/fail", "data": "eA=="})

    def test_missing_seed_does_not_seed_actor(self):
        del self.s3.objects["seeds/honey.csv"]
        with self.assertRaises(KeyError):
            self.b.run("a", {"operation": "read", "key": "seeds/honey.csv"})
        self.assertFalse(self.b.effective("a")["c"])

    def test_untrusted_actor_payload_cannot_clear(self):
        self.b.join("a", c=True)
        self.assertTrue(self.b.run("a", {"operation": "status", "actor": "clean", "c": False})["c"])

    def test_cycle_rejected(self):
        self.table.items["a"] = {"parent": "a"}
        with self.assertRaises(ValueError):
            self.b.effective("a")

    def test_seed_overwrite_rejected(self):
        with self.assertRaises(ValueError):
            self.b.run("a", {"operation": "put", "destination": "seeds/honey.csv", "data": "eA=="})

    def test_global_monitor_lease_serializes_and_releases(self):
        self.b.acquire()
        second = Broker(self.table, self.s3, self.sts, "bucket", "role")
        with self.assertRaisesRegex(RuntimeError, "monitor busy"):
            second.acquire()
        self.b.release()
        second.acquire()

    def test_all_label_joins_are_monotone(self):
        for c in (False, True):
            for d in (False, True):
                for new_c in (False, True):
                    for new_d in (False, True):
                        entity = f"{c}:{d}:{new_c}:{new_d}"
                        self.b.join(entity, c=c, d=d)
                        self.b.join(entity, c=new_c, d=new_d)
                        state = self.b.effective(entity)
                        self.assertEqual(state["c"], c or new_c)
                        self.assertEqual(state["d"], d or new_d)

    def test_untrusted_gateway_identity_rejected(self):
        with patch.dict("sys.modules", {"boto3": object()}), patch.dict("os.environ", {
            "CALLER_SESSION_PREFIX": "arn:aws:sts::123456789012:assumed-role/worker/"
        }):
            for identity in ({}, {"accessKey": "key", "userArn": "arn:aws:sts::123456789012:assumed-role/worker-evil/session"}):
                result = broker.handler({"requestContext": {"identity": identity},
                    "body": '{"actor":"trusted","operation":"status"}'}, None)
                self.assertEqual(result["statusCode"], 403)


if __name__ == "__main__":
    unittest.main()
