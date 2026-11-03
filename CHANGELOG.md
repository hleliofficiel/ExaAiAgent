# Changelog

## [3.0.0] - 2026-11-03
- Grounding: EvidenceStore + claim gate (evidence_ids required), pinned CVE KB with cve_lookup/cve_match/cve_exposure_check
- Safety: TargetScope + command guard, sandbox hardening (127.0.0.1 ports, no kube mount, no-new-privileges, dropped NET_RAW), compare_digest, timeout/async fixes, TLS verify by default
- Planning: AttackGraph with chain suggestions
- Validation: conf-v1 deterministic scoring + FP rules
- Reporting v3: unified report.json + SARIF/CSV, dedup
- Version single-sourced (exaaiagnt/version.py); OWASP Top 10:2025 docs; MCP/LangGraph orchestration docs
- Tests: 19 new tests (grounding/knowledge/safety/planning/validation/reporting)
