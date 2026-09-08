# C-/D-Taint analysis engine

This is the analysis engine for the active log-based research design. See the
[research design](../../../RESEARCH_REDESIGN.md). Unit tests validate deterministic
propagation logic; actual AWS feasibility additionally requires captured CloudTrail evidence.

This directory implements the research analysis layer that is intentionally independent of the run manifest ground truth.

## Components

- `taint_engine.py`: CloudTrail-to-CEM normalization, deterministic C-/D-Taint propagation, assertions, and trace rendering
- `analyze_aws_run.py`: CloudWatch/CloudTrail collection and per-run orchestration
- `summarize_results.py`: sanitized multi-run aggregation
- `test_taint_engine.py`: dependency-free unit tests

The engine uses Terraform outputs only as an independently configured inventory of seed resources and experiment buckets. The manifest is used to close the collection window and confirm log completeness; it is not used to infer taint.

## Semantics

- Successful seed reads create C-Taint on a role session and its credential.
- Successful AssumeRole calls propagate C-Taint to the issued session and credential.
- D-Taint starts at configured seed/classified resources and propagates only through explicit CopyObject source/destination lineage.
- A PutObject without an observable input lineage remains D-clean.
- Reusable IAM role ARNs are not C-tainted; only concrete sessions are.
- Access keys and source IPs are fingerprinted before CEM persistence. STS session tokens and secret values are never persisted by the analyzer.

## Run

```powershell
python -m unittest -v .\analysis\test_taint_engine.py
.\scripts\analyze-run.ps1 -ManifestPath ".\runs\s1a-...\manifest.json"
```

Outputs are written into the Git-ignored run directory as `collection.json`, `cem.json`, `taint-analysis.json`, and `taint-trace.md`.
