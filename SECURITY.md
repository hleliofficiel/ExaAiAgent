# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 3.1.x   | Yes       |
| < 3.1   | No        |

Only the latest 3.1.x release on `main` receives security fixes. Older versions are unsupported and will not receive backported patches.

## Reporting a vulnerability

Report vulnerabilities privately via GitHub Security Advisories:

https://github.com/hleliofficiel/ExaAiAgent/security/advisories/new

Please do **not** open a public issue for security reports. Include a description, affected versions, reproduction steps, and impact assessment where possible.

## Response timeline

- Acknowledgement within 72 hours of report
- Triage and severity assessment within 7 days
- Coordinated disclosure before any public advisory is published

These are targets, not guarantees; maintainers are a small team.

## Scope

- Supported versions: the 3.1.x line (see table above)
- Tooling: the ExaAiAgent CLI, its sandbox, and the dependencies pinned in `poetry.lock`
- Out of scope: vulnerabilities in third-party targets you scan, and issues only reproducible on unsupported versions

Scope also requires that you only test targets you own or have explicit authorization for.

v3 sandbox: non-root intent, no-new-privileges, pids_limit, 127.0.0.1-bound tool-server ports, no host credential mounts, TLS verification on by default (set EXAAI_CA_BUNDLE for Caido CA).

## Safe harbor

We consider security research conducted in good faith and in accordance with this policy to be authorized. If you make a good-faith effort to comply with this policy during your research, we will not pursue or support legal action against you, and we will work with you to understand and resolve the issue quickly.
