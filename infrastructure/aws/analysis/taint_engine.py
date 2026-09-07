#!/usr/bin/env python3
"""Normalize CloudTrail events and compute deterministic C-/D-Taint traces."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote


def fingerprint(value: str | None) -> str | None:
    if not value:
        return None
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def s3_uri(bucket: str | None, key: str | None) -> str | None:
    if not bucket or key is None:
        return None
    return f"s3://{bucket}/{key}"


def copy_source_uri(value: str | None) -> str | None:
    if not value:
        return None
    decoded = unquote(value).lstrip("/")
    if "/" not in decoded:
        return None
    bucket, key = decoded.split("/", 1)
    return s3_uri(bucket, key)


@dataclass(frozen=True)
class CEMEvent:
    event_id: str
    event_time: str
    event_source: str
    event_name: str
    success: bool
    read_only: bool | None
    actor_arn: str | None
    actor_type: str | None
    actor_issuer_arn: str | None
    actor_invoked_by: str | None
    actor_credential: str | None
    source_ip: str | None
    source_resources: tuple[str, ...] = field(default_factory=tuple)
    target_resources: tuple[str, ...] = field(default_factory=tuple)
    issued_session_arn: str | None = None
    issued_credential: str | None = None
    role_session_name: str | None = None
    source_identity: str | None = None
    error_code: str | None = None


def normalize_event(event: dict[str, Any]) -> CEMEvent | None:
    event_id = event.get("eventID")
    event_time = event.get("eventTime")
    if not event_id or not event_time:
        return None

    identity = event.get("userIdentity") or {}
    session_context = identity.get("sessionContext") or {}
    issuer = session_context.get("sessionIssuer") or {}
    request = event.get("requestParameters") or {}
    response = event.get("responseElements") or {}
    event_name = event.get("eventName") or ""
    event_source = event.get("eventSource") or ""
    sources: list[str] = []
    targets: list[str] = []
    issued_session_arn = None
    issued_credential = None
    role_session_name = request.get("roleSessionName")

    if event_source == "s3.amazonaws.com":
        target = s3_uri(request.get("bucketName"), request.get("key"))
        if event_name in {"GetObject", "GetObjectVersion", "HeadObject"} and target:
            sources.append(target)
        elif event_name == "CopyObject":
            source = copy_source_uri(request.get("x-amz-copy-source"))
            if source:
                sources.append(source)
            if target:
                targets.append(target)
        elif event_name in {"PutObject", "CompleteMultipartUpload"} and target:
            targets.append(target)
        elif event_name == "DeleteObject" and target:
            targets.append(target)
    elif event_source == "secretsmanager.amazonaws.com":
        secret_id = request.get("secretId")
        if secret_id:
            sources.append(str(secret_id))
    elif event_source == "sts.amazonaws.com" and event_name.startswith("AssumeRole"):
        role_arn = request.get("roleArn")
        if role_arn:
            targets.append(str(role_arn))
        assumed_user = response.get("assumedRoleUser") or {}
        credentials = response.get("credentials") or {}
        issued_session_arn = assumed_user.get("arn")
        issued_credential = fingerprint(credentials.get("accessKeyId"))

    source_identity = identity.get("sourceIdentity") or session_context.get("sourceIdentity")
    return CEMEvent(
        event_id=str(event_id),
        event_time=parse_time(str(event_time)).isoformat().replace("+00:00", "Z"),
        event_source=str(event_source),
        event_name=str(event_name),
        success=not bool(event.get("errorCode")),
        read_only=event.get("readOnly"),
        actor_arn=identity.get("arn"),
        actor_type=identity.get("type"),
        actor_issuer_arn=issuer.get("arn"),
        actor_invoked_by=identity.get("invokedBy"),
        actor_credential=fingerprint(identity.get("accessKeyId")),
        source_ip=fingerprint(event.get("sourceIPAddress")),
        source_resources=tuple(sources),
        target_resources=tuple(targets),
        issued_session_arn=issued_session_arn,
        issued_credential=issued_credential,
        role_session_name=role_session_name,
        source_identity=source_identity,
        error_code=event.get("errorCode"),
    )


def normalize_events(events: Iterable[dict[str, Any]]) -> list[CEMEvent]:
    unique: dict[str, CEMEvent] = {}
    for raw in events:
        normalized = normalize_event(raw)
        if normalized is not None:
            unique.setdefault(normalized.event_id, normalized)
    return sorted(unique.values(), key=lambda item: (item.event_time, item.event_id))


def is_actor_tainted(event: CEMEvent, identities: set[str], credentials: set[str]) -> bool:
    return bool(
        (event.actor_arn and event.actor_arn in identities)
        or (event.actor_credential and event.actor_credential in credentials)
    )


def add_evidence(
    collection: list[dict[str, Any]],
    seen: set[tuple[str, str, str]],
    rule: str,
    event: CEMEvent,
    subject: str,
    detail: dict[str, Any],
) -> None:
    key = (rule, event.event_id, subject)
    if key in seen:
        return
    seen.add(key)
    collection.append(
        {
            "rule": rule,
            "confidence": "EXACT",
            "event_id": event.event_id,
            "event_time": event.event_time,
            "actor_arn": event.actor_arn,
            "subject": subject,
            "detail": detail,
        }
    )


def analyze(cem: list[CEMEvent], policy: dict[str, Any]) -> dict[str, Any]:
    c_seed_resources = set(policy.get("c_seed_resources", []))
    initial_d_seeds = set(policy.get("d_seed_resources", []))
    c_identities: set[str] = set()
    c_credentials: set[str] = set()
    d_resources: set[str] = set(initial_d_seeds)
    evidence: list[dict[str, Any]] = []
    evidence_seen: set[tuple[str, str, str]] = set()
    graph_edges: list[dict[str, Any]] = []
    edge_seen: set[tuple[str, str, str, str]] = set()

    def edge(kind: str, source: str, target: str, event: CEMEvent) -> None:
        key = (kind, source, target, event.event_id)
        if key not in edge_seen:
            edge_seen.add(key)
            graph_edges.append(
                {
                    "kind": kind,
                    "source": source,
                    "target": target,
                    "event_id": event.event_id,
                    "event_time": event.event_time,
                    "confidence": "EXACT",
                }
            )

    # Seed contact is evaluated independently of event ordering.
    for event in cem:
        if not event.success:
            continue
        touched = c_seed_resources.intersection(event.source_resources)
        if not touched:
            continue
        if event.actor_arn:
            c_identities.add(event.actor_arn)
        if event.actor_credential and not event.actor_invoked_by:
            c_credentials.add(event.actor_credential)
        for resource in sorted(touched):
            subject = event.actor_arn or event.actor_credential or "unknown-actor"
            edge("C_SEED_CONTACT", resource, subject, event)
            add_evidence(
                evidence,
                evidence_seen,
                "R1_C_SEED_CONTACT",
                event,
                subject,
                {"resource": resource},
            )

    # Fixed point makes same-second/out-of-order CloudTrail delivery harmless.
    changed = True
    while changed:
        changed = False
        for event in cem:
            if not event.success:
                continue
            actor_tainted = is_actor_tainted(event, c_identities, c_credentials)
            if actor_tainted:
                if event.actor_arn and event.actor_arn not in c_identities:
                    c_identities.add(event.actor_arn)
                    changed = True
                if (
                    event.actor_credential
                    and not event.actor_invoked_by
                    and event.actor_credential not in c_credentials
                ):
                    c_credentials.add(event.actor_credential)
                    changed = True

            if event.event_source == "sts.amazonaws.com" and event.event_name.startswith("AssumeRole") and actor_tainted:
                source = event.actor_arn or event.actor_credential or "unknown-actor"
                if event.issued_session_arn:
                    if event.issued_session_arn not in c_identities:
                        c_identities.add(event.issued_session_arn)
                        changed = True
                    edge("C_DELEGATION", source, event.issued_session_arn, event)
                    add_evidence(
                        evidence,
                        evidence_seen,
                        "R2_C_DELEGATION",
                        event,
                        event.issued_session_arn,
                        {"from": source, "role_session_name": event.role_session_name},
                    )
                if event.issued_credential and event.issued_credential not in c_credentials:
                    c_credentials.add(event.issued_credential)
                    changed = True

            if event.event_source == "s3.amazonaws.com" and event.event_name == "CopyObject":
                for source_resource in event.source_resources:
                    if source_resource not in d_resources:
                        continue
                    for target_resource in event.target_resources:
                        if target_resource not in d_resources:
                            d_resources.add(target_resource)
                            changed = True
                        edge("D_COPY", source_resource, target_resource, event)
                        add_evidence(
                            evidence,
                            evidence_seen,
                            "R7_D_COPY",
                            event,
                            target_resource,
                            {
                                "source": source_resource,
                                "actor_c_tainted": actor_tainted,
                            },
                        )

    # Record direct reads of D-Taint by C-Taint after propagation reaches a fixed point.
    for event in cem:
        if not event.success or not is_actor_tainted(event, c_identities, c_credentials):
            continue
        if event.event_name not in {"GetObject", "GetObjectVersion", "GetSecretValue", "DescribeSecret"}:
            continue
        for resource in event.source_resources:
            if resource in d_resources:
                edge("C_READS_D", event.actor_arn or "unknown-actor", resource, event)
                add_evidence(
                    evidence,
                    evidence_seen,
                    "X1_C_READS_D",
                    event,
                    resource,
                    {},
                )

    event_classification: list[dict[str, Any]] = []
    class_counts = {"C_AND_D": 0, "C_ONLY": 0, "D_ONLY": 0, "CLEAN": 0}
    for event in cem:
        if not event.success:
            continue
        c_tainted = is_actor_tainted(event, c_identities, c_credentials)
        d_inputs = sorted(resource for resource in event.source_resources if resource in d_resources)
        d_outputs = sorted(resource for resource in event.target_resources if resource in d_resources)
        has_d = bool(d_inputs or d_outputs)
        if c_tainted and has_d:
            classification = "C_AND_D"
        elif c_tainted:
            classification = "C_ONLY"
        elif has_d:
            classification = "D_ONLY"
        else:
            classification = "CLEAN"
        class_counts[classification] += 1
        event_classification.append(
            {
                "event_id": event.event_id,
                "event_time": event.event_time,
                "event_name": event.event_name,
                "actor_arn": event.actor_arn,
                "classification": classification,
                "d_inputs": d_inputs,
                "d_outputs": d_outputs,
            }
        )

    assertions: list[dict[str, Any]] = []

    def assertion(name: str, passed: bool, actual: Any) -> None:
        assertions.append({"name": name, "passed": passed, "actual": actual})

    for suffix in policy.get("expected_c_session_suffixes", []):
        matches = sorted(value for value in c_identities if value.endswith(suffix))
        assertion(f"c-taint-session:{suffix}", bool(matches), matches)
    for suffix in policy.get("expected_clean_session_suffixes", []):
        matches = sorted(value for value in c_identities if value.endswith(suffix))
        assertion(f"c-clean-session:{suffix}", not matches, matches)
    for resource in policy.get("expected_d_resources", []):
        assertion(f"d-taint-resource:{resource}", resource in d_resources, resource in d_resources)
    for resource in policy.get("expected_clean_resources", []):
        assertion(f"d-clean-resource:{resource}", resource not in d_resources, resource in d_resources)
    if policy.get("expect_no_run_c_taint"):
        run_id = str(policy.get("run_id", ""))
        matches = sorted(value for value in c_identities if run_id and run_id in value)
        assertion("no-run-c-taint", not matches, matches)
    if policy.get("expect_no_derived_run_d_taint"):
        run_id = str(policy.get("run_id", ""))
        derived = sorted(value for value in d_resources - initial_d_seeds if run_id and run_id in value)
        assertion("no-derived-run-d-taint", not derived, derived)
    for classification, minimum in policy.get("expected_event_class_minimums", {}).items():
        actual = class_counts.get(classification, 0)
        assertion(f"event-class-min:{classification}", actual >= int(minimum), actual)
    for classification, maximum in policy.get("expected_event_class_maximums", {}).items():
        actual = class_counts.get(classification, 0)
        assertion(f"event-class-max:{classification}", actual <= int(maximum), actual)

    assume_events = [
        event
        for event in cem
        if event.event_source == "sts.amazonaws.com" and event.event_name.startswith("AssumeRole") and event.success
    ]
    copy_events = [
        event
        for event in cem
        if event.event_source == "s3.amazonaws.com" and event.event_name == "CopyObject" and event.success
    ]
    field_coverage = {
        "actor_arn": {
            "present": sum(1 for event in cem if event.actor_arn),
            "total": len(cem),
        },
        "actor_credential": {
            "present": sum(1 for event in cem if event.actor_credential and not event.actor_invoked_by),
            "total": sum(1 for event in cem if not event.actor_invoked_by),
        },
        "assume_issued_session": {
            "present": sum(1 for event in assume_events if event.issued_session_arn),
            "total": len(assume_events),
        },
        "assume_issued_credential": {
            "present": sum(1 for event in assume_events if event.issued_credential),
            "total": len(assume_events),
        },
        "copy_source_and_target": {
            "present": sum(1 for event in copy_events if event.source_resources and event.target_resources),
            "total": len(copy_events),
        },
        "source_identity": {
            "present": sum(1 for event in cem if event.source_identity),
            "total": len(cem),
        },
    }

    return {
        "schema_version": "1.0",
        "run_id": policy.get("run_id"),
        "scenario": policy.get("scenario"),
        "experimental_condition": policy.get("experimental_condition", "DEFAULT"),
        "source_identity_enabled": bool(policy.get("source_identity_enabled", False)),
        "analysis_passed": all(item["passed"] for item in assertions),
        "semantics": {
            "success_only": True,
            "join_confidence": "EXACT",
            "c_taint_scope": "role session and issued credential, not the reusable IAM role",
            "d_taint_scope": "seed resources and deterministic CopyObject descendants",
            "put_object_without_lineage": "does not propagate D-Taint",
        },
        "counts": {
            "cem_events": len(cem),
            "c_tainted_sessions": len(c_identities),
            "c_tainted_credentials": len(c_credentials),
            "d_tainted_resources": len(d_resources),
            "evidence": len(evidence),
            "graph_edges": len(graph_edges),
            "event_classes": class_counts,
            "source_identity_events": field_coverage["source_identity"]["present"],
        },
        "c_tainted_sessions": sorted(c_identities),
        "c_tainted_credentials": sorted(c_credentials),
        "d_tainted_resources": sorted(d_resources),
        "evidence": sorted(evidence, key=lambda item: (item["event_time"], item["event_id"], item["rule"])),
        "graph_edges": sorted(graph_edges, key=lambda item: (item["event_time"], item["event_id"], item["kind"])),
        "event_classification": event_classification,
        "field_coverage": field_coverage,
        "assertions": assertions,
    }


def render_trace_markdown(result: dict[str, Any]) -> str:
    status = "PASS" if result["analysis_passed"] else "FAIL"
    lines = [
        f"# C-/D-Taint trace: {result.get('run_id')}",
        "",
        f"- Scenario: {result.get('scenario')}",
        f"- Analysis: **{status}**",
        f"- C-tainted sessions: {result['counts']['c_tainted_sessions']}",
        f"- C-tainted credentials: {result['counts']['c_tainted_credentials']}",
        f"- D-tainted resources: {result['counts']['d_tainted_resources']}",
        f"- Evidence records: {result['counts']['evidence']}",
        f"- C∩D events: {result['counts']['event_classes']['C_AND_D']}",
        f"- C-only events: {result['counts']['event_classes']['C_ONLY']}",
        f"- D-only events: {result['counts']['event_classes']['D_ONLY']}",
        "",
        "## Assertions",
        "",
        "| Assertion | Result |",
        "|---|---|",
    ]
    for item in result["assertions"]:
        lines.append(f"| {item['name']} | {'PASS' if item['passed'] else 'FAIL'} |")
    lines.extend(
        [
            "",
            "## Intrusion timeline",
            "",
            "| Time (UTC) | Rule | Actor | Subject | Evidence eventID |",
            "|---|---|---|---|---|",
        ]
    )
    for item in result["evidence"]:
        actor = item.get("actor_arn") or "-"
        lines.append(
            f"| {item['event_time']} | {item['rule']} | {actor} | "
            f"{item['subject']} | {item['event_id']} |"
        )
    lines.extend(
        [
            "",
            "## C-/D-Taint intersection",
            "",
            "| Time (UTC) | Event | Classification | D input | D output |",
            "|---|---|---|---|---|",
        ]
    )
    for item in result["event_classification"]:
        if item["classification"] == "CLEAN":
            continue
        lines.append(
            f"| {item['event_time']} | {item['event_name']} | {item['classification']} | "
            f"{', '.join(item['d_inputs']) or '-'} | {', '.join(item['d_outputs']) or '-'} |"
        )
    lines.extend(
        [
            "",
            "## Data lineage",
            "",
            "| Time (UTC) | Edge | Source | Target |",
            "|---|---|---|---|",
        ]
    )
    for item in result["graph_edges"]:
        lines.append(
            f"| {item['event_time']} | {item['kind']} | {item['source']} | {item['target']} |"
        )
    lines.extend(
        [
            "",
            "> This local trace contains operational ARNs and resource names. The run directory is Git-ignored. "
            "Access keys and source IP addresses are stored only as SHA-256 fingerprints.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--cem-output", required=True, type=Path)
    parser.add_argument("--analysis-output", required=True, type=Path)
    parser.add_argument("--trace-output", required=True, type=Path)
    args = parser.parse_args()

    raw_events = json.loads(args.events.read_text(encoding="utf-8-sig"))
    policy = json.loads(args.policy.read_text(encoding="utf-8-sig"))
    cem = normalize_events(raw_events)
    result = analyze(cem, policy)

    args.cem_output.write_text(
        json.dumps([asdict(event) for event in cem], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    args.analysis_output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    args.trace_output.write_text(render_trace_markdown(result), encoding="utf-8")
    print(
        json.dumps(
            {
                "analysis_passed": result["analysis_passed"],
                **result["counts"],
                "analysis_output": str(args.analysis_output),
            },
            ensure_ascii=False,
        )
    )
    return 0 if result["analysis_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
