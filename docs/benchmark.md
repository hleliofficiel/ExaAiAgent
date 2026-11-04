# Benchmark harness
`benchmark/runner.py` + `benchmark/tasks/<id>/` (task.json, docker-compose.yml, checker.py). Deterministic checkers, no LLM judge. Report pass/fail, time, tokens, cost, tool calls. External baselines: XBOW validation-benchmarks, CVE-Bench (verify LICENSE before bundling).
