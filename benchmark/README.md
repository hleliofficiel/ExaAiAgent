# Benchmark
See `tasks/README.md` and `runner.py`. CI runs `python benchmark/runner.py` against Juice Shop smoke task only (no LLM keys required for env/checker validation).

## Tasks

| Task | Target | Kind |
|---|---|---|
| `juice-shop-smoke` | `http://localhost:3000` | smoke: env + HTTP 200 |
| `dvwa-smoke` | `http://localhost:4280` | smoke: env + HTTP 200 (DVWA) |
| `webgoat-smoke` | `http://localhost:8080/WebGoat` | smoke: env + HTTP 200/302 (WebGoat) |

Smoke tasks verify harness lifecycle only — they are not exploit tasks and
carry no prediction data, so the false-positive rate is `null` for them.

## Metrics

`runner.py` prints a summary aggregated by `benchmark/metrics.py`:
pass/fail counts, pass rate, total elapsed time, total tokens, total cost
(USD), total tool calls, and false-positive rate (false positives /
predictions, `null` when no run carries prediction fields —
`predicted_vulns`/`predictions` + `false_positives`).

Run: `python benchmark/runner.py [task-id ...]` (Docker required; the agent
run itself needs LLM keys and is invoked separately by the operator/CI).
