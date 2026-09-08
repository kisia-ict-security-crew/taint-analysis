"""Execute cloud-inline scenarios; keep all returned credentials in memory."""
import argparse
import base64
import json
import time
import uuid
import boto3
from botocore.credentials import Credentials
from client import invoke


def frozen(value):
    return Credentials(value["AccessKeyId"], value["SecretAccessKey"], value["SessionToken"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--worker-role", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--region", default="ap-northeast-2")
    args = parser.parse_args()
    sts = boto3.client("sts", region_name=args.region)
    run = uuid.uuid4().hex
    observations = []

    def fresh():
        return frozen(sts.assume_role(RoleArn=args.worker_role,
            RoleSessionName="exp-" + uuid.uuid4().hex, DurationSeconds=900)["Credentials"])

    def call(creds, request):
        start = time.perf_counter()
        result = invoke(args.endpoint, args.region, creds, request)
        observations.append({"operation": request["operation"],
            "elapsed_ms": (time.perf_counter() - start) * 1000,
            **{k: v for k, v in result.items() if k not in {"credentials", "data"}}})
        return result

    normal = call(fresh(), {"operation": "put", "destination": f"derived/{run}/normal", "data": "eA=="})
    assert not normal["c"] and not normal["d"]
    a = fresh()
    call(a, {"operation": "read", "key": "seeds/honey.csv"})
    b = frozen(call(a, {"operation": "delegate"})["credentials"])
    c = frozen(call(b, {"operation": "delegate"})["credentials"])
    result = call(c, {"operation": "copy", "key": "seeds/critical.csv", "destination": f"derived/{run}/copy"})
    assert result["intersection"]
    d = fresh()
    read = call(d, {"operation": "read", "key": "seeds/critical.csv"})
    result = call(d, {"operation": "put", "destination": f"derived/{run}/transformed",
        "data": base64.b64encode(base64.b64decode(read["data"]).upper()).decode()})
    assert result["d"] and not result["c"]
    # This denial distinguishes mediation from optional client instrumentation.
    raw = boto3.client("s3", region_name=args.region, aws_access_key_id=a.access_key,
        aws_secret_access_key=a.secret_key, aws_session_token=a.token)
    from botocore.exceptions import ClientError
    try:
        raw.get_object(Bucket=args.bucket, Key="seeds/honey.csv")
    except ClientError as error:
        assert error.response["Error"]["Code"] == "AccessDenied"
    else:
        raise AssertionError("Raw S3 bypass succeeded")
    print(json.dumps({"run_id": run, "status": "PASS", "raw_s3_denied": True,
                      "observations": observations}, indent=2))


if __name__ == "__main__":
    main()
