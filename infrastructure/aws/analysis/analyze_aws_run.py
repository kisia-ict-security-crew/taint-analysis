#!/usr/bin/env python3
"""Collect one AWS run from CloudTrail and execute the C-/D-Taint engine."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from taint_engine import parse_time


def command_json(command: list[str], cwd: Path) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return json.loads(completed.stdout)


def aws_json(arguments: list[str], cwd: Path) -> dict[str, Any]:
    return command_json(["aws", *arguments, "--output", "json", "--no-cli-pager"], cwd)


def terraform_outputs(terraform_dir: Path) -> dict[str, Any]:
    raw = command_json(["terraform", "output", "-json"], terraform_dir)
    return {name: item["value"] for name, item in raw.items()}


def query_cloudwatch(
    log_group: str,
    start_epoch: int,
    end_epoch: int,
    terraform_dir: Path,
) -> list[str]:
    query = "fields @timestamp, @message | sort @timestamp asc | limit 10000"
    started = aws_json(
        [
            "logs",
            "start-query",
            "--log-group-name",
            log_group,
            "--start-time",
            str(start_epoch),
            "--end-time",
            str(end_epoch),
            "--query-string",
            query,
        ],
        terraform_dir,
    )
    while True:
        time.sleep(2)
        result = aws_json(
            ["logs", "get-query-results", "--query-id", started["queryId"]],
            terraform_dir,
        )
        if result["status"] not in {"Scheduled", "Running"}:
            break
    if result["status"] != "Complete":
        raise RuntimeError(f"CloudWatch Logs Insights ended with {result['status']}")
    messages: list[str] = []
    for row in result.get("results", []):
        for field in row:
            if field.get("field") == "@message" and field.get("value"):
                messages.append(field["value"])
                break
    return messages


def configured_regions(terraform_dir: Path) -> list[str]:
    candidates = [os.getenv("AWS_REGION"), os.getenv("AWS_DEFAULT_REGION")]
    try:
        result = subprocess.run(
            ["aws", "configure", "get", "region"],
            cwd=terraform_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        if result.returncode == 0:
            candidates.append(result.stdout.strip())
    except OSError:
        pass
    candidates.append("us-east-1")
    return list(dict.fromkeys(item for item in candidates if item))


def lookup_assume_role_events(
    start: datetime,
    end_exclusive: datetime,
    terraform_dir: Path,
) -> tuple[list[str], list[dict[str, str]]]:
    messages: list[str] = []
    diagnostics: list[dict[str, str]] = []
    for region in configured_regions(terraform_dir):
        try:
            result = aws_json(
                [
                    "cloudtrail",
                    "lookup-events",
                    "--lookup-attributes",
                    "AttributeKey=EventName,AttributeValue=AssumeRole",
                    "--start-time",
                    start.isoformat(),
                    "--end-time",
                    end_exclusive.isoformat(),
                    "--region",
                    region,
                ],
                terraform_dir,
            )
            found = 0
            for item in result.get("Events", []):
                raw = item.get("CloudTrailEvent")
                if raw:
                    messages.append(raw)
                    found += 1
            diagnostics.append({"region": region, "status": "ok", "events": str(found)})
        except (subprocess.CalledProcessError, json.JSONDecodeError) as error:
            diagnostics.append({"region": region, "status": "error", "error": str(error)})
    return messages, diagnostics


def events_in_window(messages: list[str], start: datetime, end_exclusive: datetime) -> list[dict[str, Any]]:
    events: dict[str, dict[str, Any]] = {}
    for raw in messages:
        try:
            event = json.loads(raw)
            event_time = parse_time(str(event["eventTime"]))
            if start <= event_time < end_exclusive:
                event_id = str(event.get("eventID") or f"missing-id-{len(events)}")
                events.setdefault(event_id, event)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
    return sorted(events.values(), key=lambda item: (item["eventTime"], item.get("eventID", "")))


def marker_matches(events: list[dict[str, Any]], markers: list[str]) -> list[str]:
    matches: list[str] = []
    folded_markers = [str(marker).casefold() for marker in markers]
    for event in events:
        text = json.dumps(event, ensure_ascii=False, separators=(",", ":")).casefold()
        if all(marker in text for marker in folded_markers):
            matches.append(str(event.get("eventID", "")))
    return matches


def build_policy(manifest: dict[str, Any], outputs: dict[str, Any]) -> dict[str, Any]:
    run_id = manifest["run_id"]
    scenario = manifest["scenario"]
    buckets = outputs["experiment_buckets"]
    staging_copy = f"s3://{buckets['staging']}/runs/{run_id}/customer-copy.csv"
    egress_copy = f"s3://{buckets['egress']}/runs/{run_id}/customer-export.csv"
    unrelated = f"s3://{buckets['staging']}/runs/{run_id}/unrelated-output.json"
    policy: dict[str, Any] = {
        "run_id": run_id,
        "scenario": scenario,
        "experimental_condition": manifest.get("experimental_condition", "DEFAULT"),
        "source_identity_enabled": bool(manifest.get("source_identity_enabled", False)),
        "c_seed_resources": [outputs["data_seed_s3_uri"], outputs["honeytoken_secret_arn"]],
        "d_seed_resources": [
            outputs["data_seed_s3_uri"],
            outputs["honeytoken_secret_arn"],
            outputs["critical_object_s3_uri"],
        ],
        "expected_c_session_suffixes": [],
        "expected_clean_session_suffixes": [],
        "expected_d_resources": [],
        "expected_clean_resources": [],
        "expected_event_class_minimums": {},
        "expected_event_class_maximums": {},
    }
    if scenario == "S1-a":
        policy["expected_c_session_suffixes"] = [f"/{run_id}-a", f"/{run_id}-b", f"/{run_id}-c"]
        policy["expected_d_resources"] = [staging_copy, egress_copy]
        policy["expected_clean_resources"] = [unrelated]
        policy["expected_event_class_minimums"] = {"C_AND_D": 1, "C_ONLY": 1}
    elif scenario == "S2":
        policy["expected_clean_session_suffixes"] = [f"/{run_id}-a", f"/{run_id}-b", f"/{run_id}-c"]
        policy["expected_d_resources"] = [staging_copy, egress_copy]
        policy["expected_event_class_minimums"] = {"D_ONLY": 1}
        policy["expected_event_class_maximums"] = {"C_AND_D": 0, "C_ONLY": 0}
    elif scenario == "BACKGROUND":
        policy["expect_no_run_c_taint"] = True
        policy["expect_no_derived_run_d_taint"] = True
        policy["expected_event_class_maximums"] = {"C_AND_D": 0, "C_ONLY": 0, "D_ONLY": 0}
    else:
        raise ValueError(f"Unsupported scenario for taint analysis: {scenario}")
    return policy


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--terraform-dir", type=Path)
    parser.add_argument("--wait-seconds", type=int, default=900)
    parser.add_argument("--poll-seconds", type=int, default=15)
    args = parser.parse_args()

    manifest_path = args.manifest.resolve()
    terraform_dir = (args.terraform_dir or manifest_path.parents[2]).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if not manifest.get("ended_at"):
        raise RuntimeError("Manifest has no ended_at timestamp")
    outputs = terraform_outputs(terraform_dir)
    started = parse_time(manifest["started_at"])
    ended = parse_time(manifest["ended_at"])
    event_start = started.replace(microsecond=0)
    event_end_exclusive = ended.replace(microsecond=0) + timedelta(seconds=1)
    deadline = time.monotonic() + args.wait_seconds
    final_events: list[dict[str, Any]] = []
    diagnostics: list[dict[str, str]] = []

    while True:
        messages = query_cloudwatch(
            outputs["cloudwatch_log_group"],
            int(event_start.timestamp()) - 5,
            int(datetime.now(timezone.utc).timestamp()) + 120,
            terraform_dir,
        )
        management, diagnostics = lookup_assume_role_events(event_start, event_end_exclusive, terraform_dir)
        final_events = events_in_window([*messages, *management], event_start, event_end_exclusive)
        expected = [
            {
                "id": item["id"],
                "event_ids": marker_matches(final_events, item["match_all"]),
            }
            for item in manifest.get("expected_events", [])
        ]
        forbidden = [
            {
                "id": item["id"],
                "event_ids": marker_matches(final_events, item["match_all"]),
            }
            for item in manifest.get("forbidden_events", [])
        ]
        missing = [item["id"] for item in expected if not item["event_ids"]]
        violations = [item["id"] for item in forbidden if item["event_ids"]]
        collection = {
            "schema_version": "1.0",
            "run_id": manifest["run_id"],
            "scenario": manifest["scenario"],
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "event_window_start": event_start.isoformat(),
            "event_window_end_exclusive": event_end_exclusive.isoformat(),
            "unique_event_count": len(final_events),
            "expected": expected,
            "forbidden": forbidden,
            "missing_ids": missing,
            "violation_ids": violations,
            "management_lookup": diagnostics,
        }
        collection_path = manifest_path.parent / "collection.json"
        collection_path.write_text(json.dumps(collection, ensure_ascii=False, indent=2), encoding="utf-8")
        if violations:
            print(f"Collection failed: forbidden events {', '.join(violations)}", file=sys.stderr)
            return 3
        if not missing:
            break
        if time.monotonic() >= deadline:
            print(f"Collection timed out; missing: {', '.join(missing)}", file=sys.stderr)
            return 4
        print(f"Waiting for CloudTrail: {', '.join(missing)}", flush=True)
        time.sleep(args.poll_seconds)

    policy = build_policy(manifest, outputs)
    analysis_path = manifest_path.parent / "taint-analysis.json"
    cem_path = manifest_path.parent / "cem.json"
    trace_path = manifest_path.parent / "taint-trace.md"
    engine_path = Path(__file__).with_name("taint_engine.py")
    with tempfile.TemporaryDirectory(prefix="taint-analysis-") as temporary:
        temporary_path = Path(temporary)
        events_path = temporary_path / "events.json"
        policy_path = temporary_path / "policy.json"
        events_path.write_text(json.dumps(final_events, ensure_ascii=False), encoding="utf-8")
        policy_path.write_text(json.dumps(policy, ensure_ascii=False), encoding="utf-8")
        completed = subprocess.run(
            [
                sys.executable,
                str(engine_path),
                "--events",
                str(events_path),
                "--policy",
                str(policy_path),
                "--cem-output",
                str(cem_path),
                "--analysis-output",
                str(analysis_path),
                "--trace-output",
                str(trace_path),
            ],
            cwd=terraform_dir,
            check=False,
        )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
