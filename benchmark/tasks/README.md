# ExaAiAgent Benchmark (independent harness)
Deterministic checkers only — no LLM judge for exploit success. Each task dir: `task.json`, `docker-compose.yml`, `checker.py`, `README.md`.
Metrics per run: pass/fail, time-to-exploit, tokens, cost, tool calls. Baselines: XBOW validation-benchmarks (104 tasks, verify LICENSE), CVE-Bench (verify LICENSE), DVWA/Juice Shop/WebGoat for smoke.
