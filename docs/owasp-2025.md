# OWASP Top 10:2025 mapping

- A01 Broken Access Control (SSRF merged into A01) — BOLA/IDOR, SSRF-as-access-control
- A02 Security Misconfiguration (#5->#2) — default creds, verbose errors, exposed panels, cloud misconfigs
- A03 Software Supply Chain Failures — deps, CI/CD, Docker base-image CVEs (Syft+Grype/Trivy fs)
- A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Auth Failures
- A08 Software/Data Integrity Failures, A09 Logging & Alerting Failures, A10 Mishandling of Exceptional Conditions (NEW — 500s, stack traces, fail-open fuzzing)

New modules: `supply_chain_scanner`, `exceptional_conditions_fuzzer`, `logging_alerting_checker`.
