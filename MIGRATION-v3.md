# Migration v2.3.2 -> v3.0.0

| Old | New |
|---|---|
| `exaai --target ...` | `exaai scan --target ...` (bare form still works, deprecation warning) |
| `./reports/vuln_report_*.json` | `exaai_runs/<run>/report.{json,html,md}` + SARIF/CSV (`--output-format`, `--output-dir`) |
| `create_vulnerability_report` without evidence | `create_vulnerability_report(..., evidence_ids=[...])` required when EXAAI_GROUNDING=true |
| Env `LLM_BASE_URL` | `LLM_API_BASE` (both accepted during shim) |
| `EXAAI_SCAN_MODE` | `--mode` / `--profile` (env still honored) |

Run `exaai migrate --check` (dry-run helper) to validate config before scanning.


# Migration v3.0.0 -> v3.0.1

| Old | New |
|---|---|
| `create_agent(..., inherit_context=True)` default | `inherit_context=False` by default; workers no longer copy full parent history |
| No per-scan token cap | `EXAAI_MAX_SCAN_TOKENS` (default 2000000), `EXAAI_MAX_TOOL_CALLS` (500), `EXAAI_MAX_AGENTS` (8) |
| No target-scope enforcement | Set `EXAAI_TARGETS` to comma-separated authorized targets; out-of-scope URL/command calls are denied |
| No per-tool timeout | `EXAAI_TOOL_TIMEOUT` (default 120 seconds) |
| Legacy report only | Unified `report.json` is also written to the run directory |

Run the local test suite before upgrading. Docker sandbox behavior is otherwise unchanged.
