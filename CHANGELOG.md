# Changelog

## [3.0.1] - 2026-11-03
- Wire v3 dead code: TargetScope enforced in executor (EXAAI_TARGETS), sandbox retry 3x on 5xx, per-tool timeout (EXAAI_TOOL_TIMEOUT=120s)
- Budgets: EXAAI_MAX_SCAN_TOKENS/EXAAI_MAX_TOOL_CALLS/EXAAI_MAX_AGENTS + token hard-stop + circuit breaker (5 consecutive errors)
- create_agent: inherit_context defaults False, spawn cap 8
- Reporting: unified report.json via build_report persisted to run dir; to_sarif exported
- CVE intel pipeline (exaaiagnt/intelligence): FIRST EPSS + CISA KEV + OSV, provenance-stamped, offline-safe
- Verification pipeline (exaaiagnt/verification): hypothesis -> evidence -> independent check -> conf-v1 -> confirmed/suspected/false_positive + OWASP LLM Top 10:2025 map
- Benchmark harness (benchmark/): deterministic Juice Shop smoke task + runner
- Tool wrappers: nuclei (MIT, invoke-only, argv-only) + license tiers + slim-image policy (docs/tools.md)
- Docs: intelligence, verification, benchmark, tools, token-reduction, roadmap, contributing-strategy
- Tests: +9 (intelligence/verification/wrappers) -> 28 passing


## [3.0.0] - 2026-11-03
- Grounding: EvidenceStore + claim gate (evidence_ids required), pinned CVE KB with cve_lookup/cve_match/cve_exposure_check
- Safety: TargetScope + command guard, sandbox hardening (127.0.0.1 ports, no kube mount, no-new-privileges, dropped NET_RAW), compare_digest, timeout/async fixes, TLS verify by default
- Planning: AttackGraph with chain suggestions
- Validation: conf-v1 deterministic scoring + FP rules
- Reporting v3: unified report.json + SARIF/CSV, dedup
- Version single-sourced (exaaiagnt/version.py); OWASP Top 10:2025 docs; MCP/LangGraph orchestration docs (see docs/)
- Tests: 19 new tests (grounding/knowledge/safety/planning/validation/reporting)
