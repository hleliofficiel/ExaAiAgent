# Changelog

## [3.1.1] - 2026-11-12
- Security: upgrade litellm `~1.79.1` -> `>=1.95.1,<1.96.0` to remediate Socket/PyPI alerts:
  - CVE-2026-37004 / GHSA-6wvf-77m9-58rm (CVSS 9.8, CRITICAL): LiteLLM SSTI in `/prompts/test` via unsandboxed jinja2 — fixed in 1.83.7
  - CVE-2026-49468 / GHSA-4xpc-pv4p-pm3w (CVSS 9.5, CRITICAL): Host-header auth bypass on proxy management routes — fixed in 1.84.0
  - CVE-2026-35030 / GHSA-jjhc-v7c2-5hh6 (CVSS 9.4, CRITICAL): OIDC userinfo cache key collision (JWT/OIDC auth) — fixed in 1.83.0
  - Also clears remaining litellm advisories (PYSEC-2026-4066, GHSA-hhww-mrg2-969h, GHSA-g5ff-637f-6q2m) via 1.95.1
- Security floors raised: urllib3 >=2.8.0, aiohttp >=3.14.4, python-multipart >=0.0.31, cryptography >=50.0.0; lock refresh pulls fastapi 0.162.5 / starlette 1.10.0 / pyjwt 2.15.1
- openai pin relaxed >=1.99.5,<1.100.0 -> >=2.20.0,<4.0.0 (required by litellm>=1.84); websockets pin upper bound dropped; python constraint narrowed to >=3.12,<3.14 (litellm requirement)
- Version bump 3.0.1 -> 3.1.1 (pyproject, version.py fallback, CLI/TUI banners, HAR creator, docs)
- Note: Socket reported additional non-CVE alert classes (shell/network/eval/native-code/filesystem/env-var access, unidentified licenses) inherent to a security-tooling dependency tree; not individually patchable — tracked for review

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
- Tests: 30 passing (grounding, knowledge, safety, planning, validation, reporting, intelligence, verification, wrappers)


## [3.0.0] - 2026-11-03
- Grounding: EvidenceStore + claim gate (evidence_ids required), pinned CVE KB with cve_lookup/cve_match/cve_exposure_check
- Safety: TargetScope + command guard, sandbox hardening (127.0.0.1 ports, no kube mount, no-new-privileges, dropped NET_RAW), compare_digest, timeout/async fixes, TLS verify by default
- Planning: AttackGraph with chain suggestions
- Validation: conf-v1 deterministic scoring + FP rules
- Reporting v3: unified report.json + SARIF/CSV, dedup
- Version single-sourced (exaaiagnt/version.py); OWASP Top 10:2025 docs; MCP/LangGraph orchestration docs (see docs/)
- Tests: 19 new tests (grounding/knowledge/safety/planning/validation/reporting)
