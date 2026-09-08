"""Run a sanitized, bounded cost/correctness study against the AWS runtime.

Only synthetic objects are used. Temporary mine inventory is removed by exact
DynamoDB key and S3 version. Broker-produced evidence is retained as research
evidence. Credentials and data are never written to the result.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import re
import statistics
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from client import invoke


def frozen(value):
    return Credentials(value["AccessKeyId"], value["SecretAccessKey"], value["SessionToken"])


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))
    return round(ordered[index], 2)


def summary(values):
    return {
        "count": len(values),
        "mean_ms": round(statistics.mean(values), 2) if values else None,
        "p50_ms": percentile(values, 0.50),
        "p95_ms": percentile(values, 0.95),
        "min_ms": round(min(values), 2) if values else None,
        "max_ms": round(max(values), 2) if values else None,
    }


def scan_types(table):
    counts = Counter()
    kwargs = {"ProjectionExpression": "id"}
    while True:
        page = table.scan(**kwargs)
        for item in page.get("Items", []):
            counts[item["id"].split(":", 1)[0]] += 1
        key = page.get("LastEvaluatedKey")
        if not key:
            return dict(sorted(counts.items()))
        kwargs["ExclusiveStartKey"] = key


def lambda_reports(logs, log_group, start_ms, end_ms, expected, wait_seconds):
    pattern = re.compile(
        r"Duration:\s*([0-9.]+) ms\s+Billed Duration:\s*(\d+) ms.*?Memory Size:\s*(\d+) MB"
        r"(?:.*?Init Duration:\s*([0-9.]+) ms)?"
    )
    deadline = time.monotonic() + wait_seconds
    reports = []
    while True:
        reports = []
        token = None
        while True:
            kwargs = {
                "logGroupName": log_group,
                "startTime": start_ms,
                "endTime": end_ms,
                "filterPattern": '"REPORT RequestId"',
            }
            if token:
                kwargs["nextToken"] = token
            page = logs.filter_log_events(**kwargs)
            for event in page.get("events", []):
                match = pattern.search(event.get("message", ""))
                if match:
                    reports.append({
                        "duration_ms": float(match.group(1)),
                        "billed_duration_ms": int(match.group(2)),
                        "memory_mb": int(match.group(3)),
                        "init_duration_ms": float(match.group(4)) if match.group(4) else None,
                    })
            new_token = page.get("nextToken")
            if not new_token or new_token == token:
                break
            token = new_token
        if len(reports) >= expected or time.monotonic() >= deadline:
            break
        time.sleep(5)
    return {
        "observed_reports": len(reports),
        "expected_invocations": expected,
        "duration": summary([item["duration_ms"] for item in reports]),
        "billed_duration": summary([item["billed_duration_ms"] for item in reports]),
        "cold_starts": sum(1 for item in reports if item["init_duration_ms"] is not None),
        "memory_mb": reports[0]["memory_mb"] if reports else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--worker-role", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--table", required=True)
    parser.add_argument("--function-name", default="taint-runtime")
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--mine-counts", default="0,1,10,100,1000")
    parser.add_argument("--contacts", type=int, default=5)
    parser.add_argument("--direct-puts", type=int, default=20)
    parser.add_argument("--broker-puts", type=int, default=20)
    parser.add_argument("--log-wait-seconds", type=int, default=45)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    mine_counts = sorted(set(int(item) for item in args.mine_counts.split(",")))
    if not mine_counts or mine_counts[0] != 0 or mine_counts[-1] > 1000:
        raise ValueError("mine-counts must start at 0 and remain at or below 1000")

    session = boto3.Session(region_name=args.region)
    sts = session.client("sts")
    s3 = session.client("s3")
    ddb = session.resource("dynamodb").Table(args.table)
    lambda_client = session.client("lambda")
    apigateway = session.client("apigateway")
    logs = session.client("logs")
    run_id = "cost-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    mine_prefix = f"cost-study/{run_id}"
    created_mines = []
    direct_versions = []

    def fresh():
        return frozen(sts.assume_role(
            RoleArn=args.worker_role,
            RoleSessionName="cost-" + uuid.uuid4().hex,
            DurationSeconds=900,
        )["Credentials"])

    def broker_call(credentials, request):
        started = time.perf_counter()
        result = invoke(args.endpoint, args.region, credentials, request)
        return result, (time.perf_counter() - started) * 1000

    function_before = lambda_client.get_function_configuration(FunctionName=args.function_name)
    gateways_before = [item for item in apigateway.get_rest_apis(limit=500).get("items", [])
                       if item.get("name") == args.function_name]
    state_before = scan_types(ddb)
    scale_rows = [{
        "installed_mines": 0,
        "new_registry_writes": 0,
        "new_s3_puts": 0,
        "install_elapsed_ms": 0.0,
        "shared_lambda_functions": 1,
        "shared_api_gateways": len(gateways_before),
        "shared_state_tables": 1,
    }]

    def install_one(index):
        key = f"{mine_prefix}/{index:04d}.bin"
        response = s3.put_object(Bucket=args.bucket, Key=key, Body=b"x")
        entity = f"mine:s3:{args.bucket}/{key}"
        ddb.put_item(Item={
            "id": entity,
            "spec_version": "cloud-mine/v1alpha1",
            "mine_id": f"cost-mine-{run_id}-{index:04d}",
            "kind": "aws.s3-object",
            "resource": f"s3:{args.bucket}/{key}",
            "trigger": "read-success",
            "emit_c_on_read": True,
            "emit_d": False,
            "test_only": True,
        }, ConditionExpression="attribute_not_exists(id)")
        return entity, key, response.get("VersionId")

    try:
        installed = 0
        for target in mine_counts[1:]:
            started = time.perf_counter()
            with ThreadPoolExecutor(max_workers=16) as pool:
                futures = [pool.submit(install_one, index) for index in range(installed, target)]
                for future in as_completed(futures):
                    created_mines.append(future.result())
            elapsed = (time.perf_counter() - started) * 1000
            delta = target - installed
            installed = target
            scale_rows.append({
                "installed_mines": target,
                "new_registry_writes": delta,
                "new_s3_puts": delta,
                "install_elapsed_ms": round(elapsed, 2),
                "shared_lambda_functions": 1,
                "shared_api_gateways": len(gateways_before),
                "shared_state_tables": 1,
            })

        broker_start_ms = int(time.time() * 1000) - 1000
        invocations = 0
        contact_latencies = []
        contact_assertions = []
        for _ in range(args.contacts):
            result, elapsed = broker_call(fresh(), {"operation": "read", "key": "seeds/honey.csv"})
            invocations += 1
            contact_latencies.append(elapsed)
            contact_assertions.append(bool(result.get("c") and result.get("intersection")))

        direct_latencies = []
        for index in range(args.direct_puts):
            key = f"cost-study-direct/{run_id}/{index:04d}.bin"
            started = time.perf_counter()
            response = s3.put_object(Bucket=args.bucket, Key=key, Body=b"x")
            direct_latencies.append((time.perf_counter() - started) * 1000)
            direct_versions.append((key, response.get("VersionId")))

        clean_worker = fresh()
        broker_latencies = []
        broker_clean = []
        for index in range(args.broker_puts):
            result, elapsed = broker_call(clean_worker, {
                "operation": "put",
                "destination": f"derived/{run_id}/protected-{index:04d}.bin",
                "data": "eA==",
            })
            invocations += 1
            broker_latencies.append(elapsed)
            broker_clean.append(not result.get("c") and not result.get("d"))

        # Online C∩D correctness path.
        attacker = fresh()
        honey, _ = broker_call(attacker, {"operation": "read", "key": "seeds/honey.csv"})
        invocations += 1
        child_b, _ = broker_call(attacker, {"operation": "delegate"})
        invocations += 1
        child_c, _ = broker_call(frozen(child_b["credentials"]), {"operation": "delegate"})
        invocations += 1
        intersection, _ = broker_call(frozen(child_c["credentials"]), {
            "operation": "copy",
            "key": "seeds/critical.csv",
            "destination": f"derived/{run_id}/intersection.bin",
        })
        invocations += 1

        independent = fresh()
        d_read, _ = broker_call(independent, {"operation": "read", "key": "seeds/critical.csv"})
        invocations += 1
        d_only, _ = broker_call(independent, {
            "operation": "put",
            "destination": f"derived/{run_id}/d-only.bin",
            "data": base64.b64encode(base64.b64decode(d_read["data"]).upper()).decode(),
        })
        invocations += 1

        raw = session.client(
            "s3",
            aws_access_key_id=attacker.access_key,
            aws_secret_access_key=attacker.secret_key,
            aws_session_token=attacker.token,
        )
        raw_s3_denied = False
        try:
            raw.get_object(Bucket=args.bucket, Key="seeds/honey.csv")
        except ClientError as error:
            raw_s3_denied = error.response.get("Error", {}).get("Code") == "AccessDenied"

        broker_end_ms = int(time.time() * 1000) + 10_000
        state_after = scan_types(ddb)
        report = lambda_reports(
            logs,
            f"/aws/lambda/{args.function_name}",
            broker_start_ms,
            broker_end_ms,
            invocations,
            args.log_wait_seconds,
        )
        function_after = lambda_client.get_function_configuration(FunctionName=args.function_name)
        gateways_after = [item for item in apigateway.get_rest_apis(limit=500).get("items", [])
                          if item.get("name") == args.function_name]

        assertions = {
            "all_contacts_created_c_and_intersection": all(contact_assertions),
            "all_clean_broker_puts_remained_clean": all(broker_clean),
            "s1_honey_created_c": bool(honey.get("c")),
            "s1_first_intersection_observed": bool(intersection.get("c") and intersection.get("d") and intersection.get("intersection")),
            "s2_critical_read_was_d_only": bool(d_only.get("d") and not d_only.get("c") and not d_only.get("intersection")),
            "raw_worker_s3_bypass_denied": raw_s3_denied,
            "shared_lambda_unchanged": function_before.get("FunctionArn") == function_after.get("FunctionArn"),
            "shared_gateway_count_unchanged": len(gateways_before) == len(gateways_after),
            "lambda_reports_complete": report["observed_reports"] == invocations,
        }
        result = {
            "schema_version": "1.0",
            "run_id": run_id,
            "scope": "single-account synthetic AWS feasibility study",
            "status": "PASS" if all(assertions.values()) else "FAIL",
            "parameters": {
                "mine_counts": mine_counts,
                "contacts": args.contacts,
                "direct_puts": args.direct_puts,
                "broker_puts": args.broker_puts,
            },
            "mine_scaling": scale_rows,
            "latency": {
                "honey_contact": summary(contact_latencies),
                "direct_s3_put": summary(direct_latencies),
                "protected_broker_put": summary(broker_latencies),
            },
            "structural_meter": {
                "mine_install_per_instance": {"dynamodb_writes": 1, "s3_puts": 1, "broker_invocations": 0},
                "direct_normal_put_per_operation": {"s3_puts": 1},
                "protected_clean_put_per_operation": {
                    "api_gateway_requests": 1,
                    "lambda_invocations": 1,
                    "dynamodb_strong_reads": 4,
                    "dynamodb_writes": 4,
                    "s3_puts": 1,
                },
            },
            "lambda": report,
            "state_entity_counts_before": state_before,
            "state_entity_counts_after": state_after,
            "assertions": assertions,
            "notes": [
                "Cost Explorer billing is not used for this short run; request counts and billed duration are the primary cost evidence.",
                "Temporary mine registry and direct-path objects are removed after measurement.",
                "Broker-derived objects and state remain as experiment evidence.",
                "No account ID, ARN, bucket name, access key, session token, or payload is persisted in this result.",
            ],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps({
            "run_id": run_id,
            "status": result["status"],
            "lambda_reports": report["observed_reports"],
            "expected_invocations": invocations,
            "output": str(args.output),
        }))
        return 0 if result["status"] == "PASS" else 2
    finally:
        def remove_mine(item):
            entity, key, version = item
            ddb.delete_item(Key={"id": entity})
            delete = {"Bucket": args.bucket, "Key": key}
            if version:
                delete["VersionId"] = version
            s3.delete_object(**delete)

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(remove_mine, created_mines))
        for key, version in direct_versions:
            delete = {"Bucket": args.bucket, "Key": key}
            if version:
                delete["VersionId"] = version
            s3.delete_object(**delete)


if __name__ == "__main__":
    raise SystemExit(main())

