# Changelog

## [3.1.1] - 2026-11-13
- Features (this release):
  - MCP: `exaai mcp` stdio server (also `ExaAiAgent mcp` / `exaaiagent mcp`) — exaai-agent exposes itself to any MCP client (Claude Desktop, Cursor, Continue, ...)
    - Tools: `exaai_run_scan` (full scan, requires EXAAI_TARGETS match, returns concise summary — never raw report), `exaai_cve_lookup` (pinned KB), `exaai_list_runs`, `exaai_get_report`
    - stdio-only, stderr logging, error-safe `isError` responses, run_name sanitized (`^[A-Za-z0-9_.-]+$`)
    - MCP SDK 1.30.0 (already locked via litellm[proxy])
  - Dashboard v2: live event stream over WebSocket (vulnerability / agent_started / agent_completed / agent_failed / tool_completed), `counters` frame, `/api/state`, `/api/report`, `/api/export/{json,sarif,csv,html,md}`, redesigned dark UI, WS auto-reconnect, severity filters
  - Docs: dual-audience SKILL.md (users + contributors); release docs moved under `docs/`; docs/MIGRATION-v3.1.md extended; README troubleshooting reorganized
  - Tests: 222 passing (13 new dashboard tests, 7 new MCP tests); CI remains 5/5 green
- Security: upgrade litellm `~1.79.1` -> `>=1.101.3,<1.102.0` (locked 1.101.6) to remediate Socket/PyPI alerts:
  - CVE-2026-37004 / GHSA-6wvf-77m9-58rm (CVSS 9.8, CRITICAL): LiteLLM SSTI in `/prompts/test` via unsandboxed jinja2 — fixed in 1.83.7
  - CVE-2026-49468 / GHSA-4xpc-pv4p-pm3w (CVSS 9.5, CRITICAL): Host-header auth bypass on proxy management routes — fixed in 1.84.0
  - CVE-2026-35030 / GHSA-jjhc-v7c2-5hh6 (CVSS 9.4, CRITICAL): OIDC userinfo cache key collision (JWT/OIDC auth) — fixed in 1.83.0
  - GHSA-69x8-hrgq-fjj8, GHSA-53mr-6c8q-9789, GHSA-wpfp-gwwc-vwq6, GHSA-qrc4-49gv-mv9m, GHSA-7488-6r32-c95q, GHSA-v4p8-mg3p-g94g, GHSA-wpfp-gwwc-vwq6 (HIGH, proxy authz/authn) — fixed ≤1.84.0
  - GHSA-g5ff-637f-6q2m (HIGH, vertex_ai_credentials file read) — fixed in 1.95.0; PYSEC-2026-4066, GHSA-hhww-mrg2-969h — fixed ≤1.95.1; CVE-2026-114612 — fixed in 1.100.4+
- Security floors raised: urllib3 >=2.8.0, aiohttp >=3.14.4, python-multipart >=0.0.31, cryptography >=50.0.0, pypdf >=6.21.4, pillow >=13.0.0, gitpython >=3.1.59, requests >=2.33.0, certifi >=2026.10.18, dnspython >=2.9.0, fsspec >=2026.6.0, anyio >=4.14.2, idna >=3.15, lxml >=6.1.0, oauthlib >=4.0.1, soupsieve >=2.9.0, setuptools >=84.1.0, pygments >=2.20.0, azure-core >=1.38.0, graphql-core >=3.2.12 (gql ^4.4.0), python-dotenv >=1.2.2, pdfminer-six >=20251230, restrictedpython >=8.4, black >=26.3.1, virtualenv >=21.14.9, filelock >=3.20.3; lock refresh pulls fastapi 0.162.5 / starlette 1.10.0 / pyjwt 2.15.1
- Code: bandit clean (0 HIGH / 0 MEDIUM); dashboard binds 127.0.0.1 by default (was 0.0.0.0); 4 urlopen + 9 except-pass + intentional-`random` sites documented via justified `# nosec`
- openhands-aci 0.3.1 -> 0.3.3: eliminates PyPDF2 3.0.1 (PYSEC-2026-1835); pip-audit now reports 0 findings
- openai pin relaxed >=1.99.5,<1.100.0 -> >=2.20.0,<4.0.0 (required by litellm>=1.84); websockets pin upper bound dropped; python constraint narrowed to >=3.12,<3.14 (litellm requirement)
- Dev: pytest ^8.4.0 -> ^9.0.3 (locked 9.2.0; closes PYSEC-2026-1845) with libtmux >=0.62.0 (pytest-9 plugin compatibility); gql 3 -> 4.4.0 major bump required for graphql-core >=3.2.12
- Note: Socket reported additional non-CVE alert classes (shell/network/eval/native-code/filesystem/env-var access, unidentified licenses) inherent to a security-tooling dependency tree; not individually patchable — tracked for review
- Install: friendly post-install experience - ASCII banner, welcome message, quick-start steps, explicit PATH check (install.sh)
- Docs: MIGRATION-v3.1.md (upgrade notes: gql 3->4, dashboard loopback default, tool-server env token, fail-closed scope guard)
- CI: new `security` job (pip-audit against exported lock + bandit `-ll` over exaaiagnt), blocking on findings
- CI: Dependabot for weekly pip (grouped minor/patch) and github-actions updates, PRs against main
- Docs: SECURITY.md rewritten as a disclosure policy (supported versions, private advisory reporting, 72h/7d timeline, safe harbor)

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
