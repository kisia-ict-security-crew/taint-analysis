"""SigV4 client; taint computation and durable state stay in AWS."""
import argparse
import json
import urllib.request
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest


def invoke(endpoint, region, credentials, payload):
    request = AWSRequest(method="POST", url=endpoint, data=json.dumps(payload).encode(),
                         headers={"Content-Type": "application/json"})
    SigV4Auth(credentials, "execute-api", region).add_auth(request)
    with urllib.request.urlopen(urllib.request.Request(endpoint, data=request.data,
            headers=dict(request.headers), method="POST"), timeout=30) as response:
        return json.load(response)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--request", required=True, help="JSON operation")
    args = parser.parse_args()
    result = invoke(args.endpoint, args.region,
                    boto3.Session().get_credentials().get_frozen_credentials(),
                    json.loads(args.request))
    # Credential delegation is consumed programmatically, never printed.
    print(json.dumps({k: v for k, v in result.items() if k not in {"credentials", "data"}}))
