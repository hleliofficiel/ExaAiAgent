# Tool integration policy (Apache-2.0 stays clean)
Tier A (MIT/Apache/BSD): bundle pinned static binaries (nuclei, httpx, katana, interactsh, subfinder, ffuf, dalfox, graphw00f*, wafw00f, trivy, grype, prowler, gitleaks, bandit). Tier B (GPL/LGPL/AGPL/NPSL: sqlmap, arjun, semgrep, nmap, trufflehog, masscan): invoke-only as external processes, never vendored/linked. Tier C (proprietary: Burp/Caido): never bundled, user-supplied binary via env only.
Image: slim Debian base, multi-stage profiles (core/recon/web/cloud), pinned version+SHA per tool, on-demand `exaai tools install <name>`, SBOM via Syft/Trivy, THIRD_PARTY_NOTICES.md from SBOM. Target core <800MB.
Each wrapper: argv-only (never shell=True), TargetScope check, timeout, JSONL/SARIF parse -> EvidenceStore evidence_ids.
