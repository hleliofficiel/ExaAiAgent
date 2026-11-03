# Migration v2.3.2 -> v3.0.0

| Old | New |
|---|---|
| `exaai --target ...` | `exaai scan --target ...` (bare form still works, deprecation warning) |
| `./reports/vuln_report_*.json` | `exaai_runs/<run>/report.{json,html,md}` + SARIF/CSV (`--output-format`, `--output-dir`) |
| `create_vulnerability_report` without evidence | `create_vulnerability_report(..., evidence_ids=[...])` required when EXAAI_GROUNDING=true |
| Env `LLM_BASE_URL` | `LLM_API_BASE` (both accepted during shim) |
| `EXAAI_SCAN_MODE` | `--mode` / `--profile` (env still honored) |

Run `exaai migrate --check` (dry-run helper) to validate config before scanning.
