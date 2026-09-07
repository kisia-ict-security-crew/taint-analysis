import unittest

try:
    from .taint_engine import analyze, normalize_events
except ImportError:  # Direct execution from the analysis directory.
    from taint_engine import analyze, normalize_events


ACCOUNT = "111122223333"
CRITICAL = "s3://critical/classified/customer.csv"
DATA_SEED = "s3://critical/decoy/seed.csv"
SECRET_SEED = f"arn:aws:secretsmanager:ap-northeast-2:{ACCOUNT}:secret:decoy"


def identity(arn: str, access_key: str) -> dict:
    return {"type": "AssumedRole", "arn": arn, "accessKeyId": access_key}


def event(
    event_id: str,
    second: int,
    name: str,
    source: str,
    actor: dict,
    request: dict,
    response: dict | None = None,
    error: str | None = None,
) -> dict:
    item = {
        "eventID": event_id,
        "eventTime": f"2026-01-01T00:00:{second:02d}Z",
        "eventName": name,
        "eventSource": source,
        "userIdentity": actor,
        "requestParameters": request,
        "responseElements": response,
    }
    if error:
        item["errorCode"] = error
    return item


def assume(event_id: str, second: int, actor: dict, role: str, session: str, issued_key: str) -> dict:
    role_name = role.rsplit("/", 1)[-1]
    return event(
        event_id,
        second,
        "AssumeRole",
        "sts.amazonaws.com",
        actor,
        {"roleArn": role, "roleSessionName": session},
        {
            "assumedRoleUser": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role_name}/{session}"},
            "credentials": {"accessKeyId": issued_key, "sessionToken": "must-not-be-normalized"},
        },
    )


class TaintEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.run_id = "s1a-test"
        self.actor_a = f"arn:aws:sts::{ACCOUNT}:assumed-role/actor-a/{self.run_id}-a"
        self.pivot_b = f"arn:aws:sts::{ACCOUNT}:assumed-role/pivot-b/{self.run_id}-b"
        self.pivot_c = f"arn:aws:sts::{ACCOUNT}:assumed-role/pivot-c/{self.run_id}-c"
        self.staging = f"s3://staging/runs/{self.run_id}/customer-copy.csv"
        self.egress = f"s3://egress/runs/{self.run_id}/customer-export.csv"
        self.control = f"s3://staging/runs/{self.run_id}/unrelated-output.json"

    def policy(self, scenario: str = "S1-a") -> dict:
        return {
            "run_id": self.run_id,
            "scenario": scenario,
            "c_seed_resources": [DATA_SEED, SECRET_SEED],
            "d_seed_resources": [DATA_SEED, SECRET_SEED, CRITICAL],
            "expected_c_session_suffixes": (
                [f"/{self.run_id}-a", f"/{self.run_id}-b", f"/{self.run_id}-c"]
                if scenario == "S1-a"
                else []
            ),
            "expected_clean_session_suffixes": (
                [f"/{self.run_id}-a", f"/{self.run_id}-b", f"/{self.run_id}-c"]
                if scenario == "S2"
                else []
            ),
            "expected_d_resources": [self.staging, self.egress],
            "expected_clean_resources": [self.control],
        }

    def scenario_events(self, touch_seed: bool = True) -> list[dict]:
        events = []
        if touch_seed:
            events.append(
                event(
                    "seed",
                    1,
                    "GetObject",
                    "s3.amazonaws.com",
                    identity(self.actor_a, "TEMP-A"),
                    {"bucketName": "critical", "key": "decoy/seed.csv"},
                )
            )
        events.extend(
            [
                assume(
                    "a-b",
                    2,
                    identity(self.actor_a, "TEMP-A"),
                    f"arn:aws:iam::{ACCOUNT}:role/pivot-b",
                    f"{self.run_id}-b",
                    "TEMP-B",
                ),
                assume(
                    "b-c",
                    3,
                    identity(self.pivot_b, "TEMP-B"),
                    f"arn:aws:iam::{ACCOUNT}:role/pivot-c",
                    f"{self.run_id}-c",
                    "TEMP-C",
                ),
                event(
                    "read-critical",
                    4,
                    "GetObject",
                    "s3.amazonaws.com",
                    identity(self.pivot_c, "TEMP-C"),
                    {"bucketName": "critical", "key": "classified/customer.csv"},
                ),
                event(
                    "copy-one",
                    5,
                    "CopyObject",
                    "s3.amazonaws.com",
                    identity(self.pivot_c, "TEMP-C"),
                    {
                        "bucketName": "staging",
                        "key": f"runs/{self.run_id}/customer-copy.csv",
                        "x-amz-copy-source": "critical/classified/customer.csv",
                    },
                ),
                event(
                    "copy-two",
                    6,
                    "CopyObject",
                    "s3.amazonaws.com",
                    identity(self.pivot_c, "TEMP-C"),
                    {
                        "bucketName": "egress",
                        "key": f"runs/{self.run_id}/customer-export.csv",
                        "x-amz-copy-source": f"staging/runs/{self.run_id}/customer-copy.csv",
                    },
                ),
                event(
                    "control",
                    7,
                    "PutObject",
                    "s3.amazonaws.com",
                    identity(self.pivot_c, "TEMP-C"),
                    {"bucketName": "staging", "key": f"runs/{self.run_id}/unrelated-output.json"},
                ),
            ]
        )
        return events

    def test_s1a_propagates_c_and_d_taint_but_not_control(self) -> None:
        cem = normalize_events(self.scenario_events(touch_seed=True))
        result = analyze(cem, self.policy("S1-a"))
        self.assertTrue(result["analysis_passed"])
        self.assertIn(self.actor_a, result["c_tainted_sessions"])
        self.assertIn(self.pivot_b, result["c_tainted_sessions"])
        self.assertIn(self.pivot_c, result["c_tainted_sessions"])
        self.assertIn(self.egress, result["d_tainted_resources"])
        self.assertNotIn(self.control, result["d_tainted_resources"])
        self.assertTrue(all(value.startswith("sha256:") for value in result["c_tainted_credentials"]))

    def test_denied_seed_access_does_not_create_c_taint(self) -> None:
        denied = event(
            "denied",
            1,
            "GetObject",
            "s3.amazonaws.com",
            identity(self.actor_a, "TEMP-A"),
            {"bucketName": "critical", "key": "decoy/seed.csv"},
            error="AccessDenied",
        )
        result = analyze(normalize_events([denied]), {**self.policy("S2"), "expected_d_resources": []})
        self.assertEqual([], result["c_tainted_sessions"])

    def test_s2_propagates_d_without_c_taint(self) -> None:
        cem = normalize_events(self.scenario_events(touch_seed=False))
        result = analyze(cem, self.policy("S2"))
        self.assertTrue(result["analysis_passed"])
        self.assertEqual([], result["c_tainted_sessions"])
        self.assertIn(self.egress, result["d_tainted_resources"])

    def test_duplicate_event_ids_are_deduplicated(self) -> None:
        item = self.scenario_events(touch_seed=True)[0]
        self.assertEqual(1, len(normalize_events([item, item])))


if __name__ == "__main__":
    unittest.main()
