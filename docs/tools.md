# Tool integration policy (Apache-2.0 stays clean)
Tier A (MIT/Apache/BSD): bundle pinned static binaries (nuclei, httpx, katana, interactsh, subfinder, ffuf, dalfox, graphw00f*, wafw00f, trivy, grype, prowler, gitleaks, bandit). Tier B (GPL/LGPL/AGPL/NPSL: sqlmap, arjun, semgrep, nmap, trufflehog, masscan): invoke-only as external processes, never vendored/linked. Tier C (proprietary: Burp/Caido): never bundled, user-supplied binary via env only.
Image: slim Debian base, multi-stage profiles (core/recon/web/cloud), pinned version+SHA per tool, on-demand `exaai tools install <name>`, SBOM via Syft/Trivy, THIRD_PARTY_NOTICES.md from SBOM. Target core <800MB.
Each wrapper: argv-only (never shell=True), TargetScope check, timeout, JSONL/SARIF parse -> EvidenceStore evidence_ids.

## Priority 1 — activated dead tools (registered, sandbox_execution=True)

All four are pure analysis (no network I/O). They return structured dicts and
validate inputs (oversize/invalid -> `{"success": False, "error": ...}`).

- `smart_fuzz_parameter_tool(param_name, param_value, categories=None)` —
  `exaaiagnt/tools/smart_fuzzer.py`. Context-aware payload selection.
- `analyze_http_response_tool(response_body, status_code=200, response_time_ms=0, headers_json=None)` —
  `exaaiagnt/tools/response_analyzer.py`. Error/leakage detection.
- `create_vulnerability_report_tool(vuln_type, url, parameter, payload, evidence)` —
  `exaaiagnt/tools/vuln_validator.py`. PoC + remediation + CVSS.
- `detect_waf_and_bypass_tool(status_code, body, payload, headers_json=None)` —
  `exaaiagnt/tools/waf_bypass.py`. WAF detection + bypass variants.

## Priority 3 — web tool wrappers (argv-only, never shell=True)

Each wrapper builds an explicit argv list, enforces a flag allowlist where
extra flags are accepted, applies a timeout, returns structured dicts, and
fails gracefully (`<tool>_not_installed`) when the binary is absent.

- **nuclei** (`wrappers/nuclei_wrapper.py`, Tier-A MIT): `build_nuclei_argv`,
  `parse_nuclei_jsonl`, `run_nuclei`. Templates: update with
  `nuclei -update-templates` on a pinned release; record the template
  version in scan evidence. Do not vendor templates without pinning
  version+SHA.
- **ZAP** (`wrappers/zap_wrapper.py`, Tier-B GPL, invoke-only — never
  vendored): `zap_daemon_status`, `build_zap_daemon_argv`,
  `start_zap_daemon`. Daemon binds to `127.0.0.1` only; external binds are
  rejected. Missing binary -> `zap_not_installed`. Start with
  `zaproxy -daemon -host 127.0.0.1 -port 8090` (see builder for full argv).
- **OAST/interactsh** (`wrappers/oast_wrapper.py`, Tier-A MIT, internal only):
  `new_oast_token`, `build_interactsh_argv`, `parse_interactsh_json`,
  `poll_interactsh`. No external exfil: external `-oast-domain` values are
  rejected; tokens are generated locally. Missing binary ->
  `interactsh_not_installed`.
- **httpx + katana + ffuf** (`wrappers/httpx_katana_wrapper.py`, Tier-A MIT):
  `build_httpx_argv`/`run_httpx`, `build_katana_argv`/`run_katana`,
  `build_ffuf_argv`/`run_ffuf`. Extra flags must be on a per-tool allowlist
  (unknown flags raise `ValueError`); ffuf wordlists must be absolute
  `.txt` paths and the URL must contain `FUZZ`. Missing binary ->
  `<tool>_not_installed`.
