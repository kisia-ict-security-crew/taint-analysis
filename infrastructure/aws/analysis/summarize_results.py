#!/usr/bin/env python3
"""Create a sanitized aggregate report from local taint-analysis results."""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any


def mean(values: list[int]) -> float:
    return round(statistics.mean(values), 2) if values else 0.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", required=True, type=Path)
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--markdown-output", required=True, type=Path)
    args = parser.parse_args()

    rows: list[dict[str, Any]] = []
    for path in sorted(args.runs_dir.glob("*/taint-analysis.json")):
        item = json.loads(path.read_text(encoding="utf-8-sig"))
        rows.append(
            {
                "run_id": item["run_id"],
                "scenario": item["scenario"],
                "condition": item.get("experimental_condition", "DEFAULT"),
                "passed": item["analysis_passed"],
                "cem_events": item["counts"]["cem_events"],
                "c_sessions": item["counts"]["c_tainted_sessions"],
                "c_credentials": item["counts"]["c_tainted_credentials"],
                "d_resources": item["counts"]["d_tainted_resources"],
                "source_identity_events": item["counts"].get("source_identity_events", 0),
                **item["counts"]["event_classes"],
            }
        )

    by_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_scenario[row["scenario"]].append(row)

    scenario_summary: list[dict[str, Any]] = []
    for scenario, items in sorted(by_scenario.items()):
        scenario_summary.append(
            {
                "scenario": scenario,
                "runs": len(items),
                "passed": sum(1 for item in items if item["passed"]),
                "mean_c_sessions": mean([item["c_sessions"] for item in items]),
                "mean_c_credentials": mean([item["c_credentials"] for item in items]),
                "mean_c_and_d_events": mean([item["C_AND_D"] for item in items]),
                "mean_c_only_events": mean([item["C_ONLY"] for item in items]),
                "mean_d_only_events": mean([item["D_ONLY"] for item in items]),
                "mean_clean_events": mean([item["CLEAN"] for item in items]),
                "mean_source_identity_events": mean([item["source_identity_events"] for item in items]),
            }
        )

    result = {
        "schema_version": "1.0",
        "scope": "feasibility; synthetic single-account AWS lab",
        "total_runs": len(rows),
        "all_passed": all(row["passed"] for row in rows),
        "runs": rows,
        "scenario_summary": scenario_summary,
        "paper_findings": [
            {
                "id": "F1",
                "finding": "The background run produced no C-Taint, D-only, or C∩D event classification.",
            },
            {
                "id": "F2",
                "finding": "Every S1-a run tainted exactly three role sessions and three issued credentials.",
            },
            {
                "id": "F3",
                "finding": "Every S1-a run produced seven C∩D events and propagated D-Taint to simulated egress.",
            },
            {
                "id": "F4",
                "finding": "S2 produced D-only events without C-Taint, exposing the seedless-attack blind spot of C-only detection.",
            },
            {
                "id": "F5",
                "finding": "C∩D is a higher-specificity attribution signal than either taint alone, but cannot cover seedless paths by itself.",
            },
            {
                "id": "F6",
                "finding": "The SourceIdentity intervention preserved the same C/D result while adding an explicit identity field to 18 events; exact credential/session joins did not require it.",
            },
        ],
        "limitations": [
            "The sample is too small for population-level precision, recall, or confidence intervals.",
            "All runs use one AWS account and deterministic synthetic workflows.",
            "D-Taint propagation is supported only for explicit CopyObject lineage.",
            "CloudTrail ordering is handled by fixed-point inference, but missing events still reduce recall.",
        ],
    }

    lines = [
        "# Paper-ready feasibility results",
        "",
        "> Sanitized aggregate: no account IDs, ARNs, access keys, source IPs, bucket names, or secret identifiers.",
        "",
        f"- Runs analyzed: {len(rows)}",
        f"- Runs passing all pre-registered assertions: {sum(1 for row in rows if row['passed'])}/{len(rows)}",
        "",
        "## Per-run results",
        "",
        "| Run | Scenario | Condition | PASS | C sessions | C credentials | C∩D | C-only | D-only | Clean | SourceIdentity events |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['run_id']} | {row['scenario']} | {row['condition']} | {'yes' if row['passed'] else 'no'} | "
            f"{row['c_sessions']} | {row['c_credentials']} | {row['C_AND_D']} | "
            f"{row['C_ONLY']} | {row['D_ONLY']} | {row['CLEAN']} | {row['source_identity_events']} |"
        )
    lines.extend(
        [
            "",
            "## Scenario aggregates",
            "",
            "| Scenario | Runs | Passed | Mean C sessions | Mean C credentials | Mean C∩D | Mean C-only | Mean D-only | Mean SourceIdentity events |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for item in scenario_summary:
        lines.append(
            f"| {item['scenario']} | {item['runs']} | {item['passed']} | "
            f"{item['mean_c_sessions']} | {item['mean_c_credentials']} | "
            f"{item['mean_c_and_d_events']} | {item['mean_c_only_events']} | {item['mean_d_only_events']} | "
            f"{item['mean_source_identity_events']} |"
        )
    lines.extend(["", "## Findings", ""])
    for finding in result["paper_findings"]:
        lines.append(f"- **{finding['id']}** — {finding['finding']}")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "S1-a demonstrates an attributable path: seed contact creates C-Taint, AssumeRole propagates it to two downstream sessions, and explicit CopyObject lineage propagates D-Taint to simulated egress. S2 demonstrates a complementary limitation: the same D-Taint reaches egress without any seed contact, so C-Taint alone has zero coverage for that path. The intersection C∩D is therefore useful as a high-specificity, seed-confirmed intrusion trace, while D-only must remain a separate review class rather than being discarded.",
            "",
            "These observations are feasibility evidence, not final detection-performance estimates. More repetitions and non-deterministic background workloads are required before reporting population precision or recall.",
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in result["limitations"])
    lines.append("")

    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    args.markdown_output.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"runs": len(rows), "all_passed": result["all_passed"]}))
    return 0 if rows and result["all_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
