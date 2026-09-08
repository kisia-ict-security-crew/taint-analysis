"""Inline, monotone taint reference monitor. No CloudTrail input.

A DynamoDB lease serializes this research implementation. Data and
credentials are released only after durable label updates.
"""
import base64
import hashlib
import json
import os
import time
import uuid


class Broker:
    def __init__(self, table, s3, sts, bucket, role):
        self.table, self.s3, self.sts = table, s3, sts
        self.bucket, self.role = bucket, role

    def get(self, entity):
        return self.table.get_item(Key={"id": entity}, ConsistentRead=True).get("Item", {})

    def join(self, entity, c=False, d=False):
        old = self.get(entity)
        changes = {k: True for k, v in {"c": c, "d": d}.items() if v and not old.get(k)}
        if changes:
            self.table.update_item(
                Key={"id": entity},
                UpdateExpression="SET " + ", ".join(f"#{k} = :yes" for k in changes),
                ExpressionAttributeNames={f"#{k}": k for k in changes},
                ExpressionAttributeValues={":yes": True},
            )
        return {**old, **changes}

    def effective(self, entity):
        c = d = False
        seen = set()
        while entity:
            if entity in seen or len(seen) >= 16:
                raise ValueError("Invalid or excessive delegation depth")
            seen.add(entity)
            state = self.get(entity)
            c, d = c or state.get("c", False), d or state.get("d", False)
            entity = state.get("parent")
        return {"c": c, "d": d, "depth": len(seen)}

    @staticmethod
    def credential(key):
        return "credential:" + hashlib.sha256(key.encode()).hexdigest()

    def resource(self, key):
        if not isinstance(key, str) or not key or len(key) > 512:
            raise ValueError("Invalid object key")
        entity = "s3:" + self.bucket + "/" + key
        mine = self.get("mine:" + entity)
        if not mine and not key.startswith("derived/"):
            raise ValueError("Object outside mediated inventory")
        return entity, self.join(entity, d=mine.get("emit_d", False)), mine

    def destination(self, key, c, d):
        entity, _, _ = self.resource(key)
        if not key.startswith("derived/"):
            raise ValueError("Seeds are immutable")
        # Reserve a new name before side effects. Failed writes leave a conservative
        # reservation; retries use a new key. No overwrite/version ambiguity.
        self.table.put_item(Item={"id": entity, "c": c, "d": d, "reserved": True},
                            ConditionExpression="attribute_not_exists(id)")
        return entity

    def evidence(self, actor, operation, source, target, c, d):
        self.table.put_item(Item={"id": "edge:" + uuid.uuid4().hex, "actor": actor,
                                  "operation": operation, "source": source,
                                  "target": target, "c": bool(c), "d": bool(d),
                                  "intersection": bool(c and d)})

    def acquire(self):
        """Obtain the single research monitor lease before reading label state.

        Lambda's own concurrency is not a correctness mechanism: small/new AWS
        accounts cannot reserve capacity while retaining their required
        unreserved pool. The lease exceeds the Lambda timeout (20 seconds), so a
        timed-out owner cannot still execute when another invocation acquires it.
        """
        self.lock_owner = uuid.uuid4().hex
        now = int(time.time())
        try:
            self.table.update_item(
                Key={"id": "lock:global"},
                UpdateExpression="SET lease_until = :lease, lock_owner = :owner",
                ConditionExpression="attribute_not_exists(lease_until) OR lease_until < :now",
                ExpressionAttributeValues={":lease": now + 60, ":owner": self.lock_owner, ":now": now},
            )
        except Exception as error:
            raise RuntimeError("monitor busy or state unavailable") from error

    def release(self):
        try:
            self.table.update_item(
                Key={"id": "lock:global"},
                UpdateExpression="SET lease_until = :released",
                ConditionExpression="lock_owner = :owner",
                ExpressionAttributeValues={":released": 0, ":owner": self.lock_owner},
            )
        except Exception:
            # A failed release retains the lease; this is fail-closed until expiry.
            pass

    def run(self, actor, request):
        state = self.effective(actor)
        op = request.get("operation")
        if op == "status":
            return state
        if op == "delegate":
            if state["depth"] >= 15:
                raise ValueError("Delegation depth limit")
            response = self.sts.assume_role(RoleArn=self.role,
                RoleSessionName="taint-" + uuid.uuid4().hex,
                DurationSeconds=900)
            credentials = response["Credentials"]
            child = self.credential(credentials["AccessKeyId"])
            self.table.put_item(Item={"id": child, "parent": actor,
                "c": state["c"], "d": state["d"]},
                ConditionExpression="attribute_not_exists(id)")
            self.evidence(actor, op, actor, child, state["c"], state["d"])
            return {"credentials": {k: str(v) for k, v in credentials.items()}}
        if op not in {"read", "copy", "put"}:
            raise ValueError("Unsupported operation")
        source, label, content = "", {}, None
        if op in {"read", "copy"}:
            key = request.get("key")
            source, label, mine = self.resource(key)
            # Fetch succeeds before R1; bounded reads prevent proxy payload overflow.
            response = self.s3.get_object(Bucket=self.bucket, Key=key)
            stream = response["Body"]
            try:
                content = stream.read(65537)
            finally:
                stream.close()
            if len(content) > 65536:
                raise ValueError("Prototype limit: 64 KiB per object")
            state = {**state, **self.join(actor,
                c=state["c"] or mine.get("emit_c_on_read", False),
                d=state["d"] or label.get("d", False))}
            # Reading a C-marked artifact does NOT prove execution/control transfer.
            self.join(source, c=state["c"])
        c, d = state["c"], state["d"]
        target = source
        if op in {"copy", "put"}:
            if op == "put":
                content = base64.b64decode(request.get("data", ""), validate=True)
                if len(content) > 65536:
                    raise ValueError("Prototype limit: 64 KiB per object")
            key = request.get("destination")
            target = self.destination(key, c, d)
            # Labels are committed before output becomes visible, including resource tags.
            self.s3.put_object(Bucket=self.bucket, Key=key, Body=content,
                Tagging=f"taint-c={str(c).lower()}&taint-d={str(d).lower()}")
        self.evidence(actor, op, source, target, c, d)
        result = {"c": c, "d": d, "intersection": bool(c and d), "resource": target}
        if op == "read":
            result["data"] = base64.b64encode(content).decode()
        return result


def handler(event, context):
    import boto3
    try:
        identity = event.get("requestContext", {}).get("identity", {})
        arn, key = identity.get("userArn", ""), identity.get("accessKey")
        prefix = os.environ["CALLER_SESSION_PREFIX"]
        if not key or not arn.startswith(prefix) or not arn[len(prefix):]:
            return {"statusCode": 403, "body": '{"error":"untrusted caller"}'}
        body = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            body = base64.b64decode(body).decode()
        request = json.loads(body)
        if not isinstance(request, dict):
            raise ValueError("Object request required")
        broker = Broker(boto3.resource("dynamodb").Table(os.environ["TABLE"]),
            boto3.client("s3"), boto3.client("sts"), os.environ["BUCKET"],
            os.environ["WORKER_ROLE"])
        broker.acquire()
        try:
            result = broker.run(broker.credential(key), request)
        finally:
            broker.release()
        return {"statusCode": 200, "headers": {"Cache-Control": "no-store"},
                "body": json.dumps(result)}
    except (ValueError, TypeError):
        return {"statusCode": 400, "body": '{"error":"invalid request"}'}
    except Exception:
        # Never emit request bodies, credentials, or data to logs.
        return {"statusCode": 503, "body": '{"error":"operation not released; state may be conservatively retained"}'}
