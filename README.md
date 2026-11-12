<p align="center">
  <img src=".github/logo.png" width="150" alt="ExaAiAgent Logo">
</p>

<h1 align="center">ExaAiAgent</h1>

<h2 align="center">Advanced AI-Powered Cybersecurity Agent for Comprehensive Penetration Testing</h2>

<div align="center">

[![Python](https://img.shields.io/pypi/pyversions/exaai-agent?color=3776AB)](https://pypi.org/project/exaai-agent/)
[![PyPI](https://img.shields.io/pypi/v/exaai-agent?color=10b981)](https://pypi.org/project/exaai-agent/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.1.1-00d4ff.svg)]()

</div>

<br>

> [!TIP]
> **v3.1.1 - latest.** Evidence-grounded findings, CVE intelligence (EPSS / CISA KEV / OSV), independent verification, scoped execution, token budgets, and reproducible reporting.
>
> **Connect Your Agent:** Point another AI agent at the repository skill:
> ```
> Read https://raw.githubusercontent.com/hleliofficiel/ExaAiAgent/main/SKILL.md and follow the instructions to operate ExaAiAgent
> ```

---

## v3.1.1 at a glance

| Area | What changed |
|---|---|
| Grounding | Every tool result gets an `evidence_id`; reports require evidence, invented CVE/version claims are rejected. |
| CVE intelligence | FIRST EPSS + CISA KEV + OSV + GitHub Advisories with provenance and version-range matching (`exaaiagnt/intelligence/`). |
| Verification | `hypothesis -> evidence -> independent check -> conf-v1 -> confirmed / suspected / false_positive`, with hardening downgrades for high-severity injection, secret leak, and cross-tenant RAG evidence. |
| Safety & scope | `TargetScope` enforced in the executor when `EXAAI_TARGETS` is set; command guard, blocklist, and proxy linkage deny out-of-scope execution with `ScopeDecision` evidence. Sandbox runs on 127.0.0.1, without host `~/.kube` mount, `no-new-privileges`, and without NET_RAW. |
| Budgets | Per-scan token / tool-call / spawn caps (`EXAAI_MAX_SCAN_TOKENS`, `EXAAI_MAX_TOOL_CALLS`, `EXAAI_MAX_AGENTS`), token hard-stop, and a circuit breaker after 5 consecutive tool errors. `create_agent` defaults to `inherit_context=False` with a spawn cap of 8. |
| Reporting | Unified `report.json` via `build_report`, plus SARIF / CSV / HTML / Markdown exports, persisted to `exaai_runs/<run-name>/`. |
| Tools & wrappers | 78 registered tools. Nuclei (invoke-only, argv-only), ZAP, httpx/katana, and OAST wrappers with license tiers. HAR import/export, browser JS analysis (DOM XSS, postMessage, Service Worker, bundle secrets), API auth/OpenAPI checks, secrets scanning, SBOM triage, and cloud checks. |
| Coordination | `RunState` save / load / resume, bounded task queue, budget guard, and stuck detection, exposed as `coordination_*` tools. |
| LLM / MCP / RAG | Offline OWASP LLM Top 10 (2025) checkers: prompt-injection detection, secret-leak detection, MCP manifest audit, and RAG provenance / cross-tenant checks. |
| Benchmark | Deterministic smoke harness for Juice Shop, DVWA, and WebGoat (`benchmark/`). |
| Prompts | 64 prompt modules, including OWASP LLM Top 10 2025, supply-chain / SBOM triage, exceptional-conditions fail-open, and grounded CVE verification. |
| CI | Lint, test, type-check, and smoke jobs green on `main`. Node pinned to 22 LTS in Docker. |

### Previous versions (brief history)

| Version | Summary |
|---|---|
| v3.0.0 | Anti-hallucination grounding (`evidence_id` + EvidenceStore), pinned CVE KB, sandbox hardening, attack-graph planning, conf-v1 validation, reporting v3 (SARIF/CSV/HTML), single-sourced version. |
| v2.3.2 | K8s scanner tool registration fix, run persistence (`exaai_runs/<run>/`), lint pass. |
| v2.2.5 | CI on PRs, import-safe tool server, multi-tool LLM responses, prompt-module merging, TUI target queue. |
| v2.2.2 - v2.0 | Recon modules (subdomain / port / fingerprint), K8s / Azure / GCP modules, React2Shell CVE detection, auto-discovery, install.sh. |

Details: see CHANGELOG.md, MIGRATION-v3.md, MIGRATION-v3.1.md, SECURITY.md, and docs/.

---

## Overview

ExaAiAgent is an AI-powered security testing framework that runs like a penetration tester: it executes code dynamically, finds vulnerabilities, and validates them with proof-of-concepts before reporting. It is built for developers and security teams who need fast, accurate testing with evidence behind every claim.

**Key capabilities:**

- Full security toolkit out of the box, across web, API, cloud, container, and LLM targets
- Teams of specialized agents that collaborate and share discoveries
- Real validation with PoCs, not ungrounded claims
- Developer-first CLI with actionable, reproducible reports
- Multi-LLM support through LiteLLM: OpenAI, Anthropic, Gemini, OpenRouter, Ollama, and any compatible provider
- Smart module loading that auto-detects GraphQL, WebSocket, OAuth, recon, and other attack surfaces

**Use cases:** application security testing, rapid penetration testing, bug-bounty research, CI/CD gating, API security testing (REST, GraphQL, gRPC), and cloud configuration review.

---

## Quick Start

**Prerequisites:** Docker (running), Python 3.12+, and an LLM provider (OpenAI, Anthropic, OpenRouter, Ollama, or any compatible provider).

```bash
pip install exaai-agent
# or: pipx install exaai-agent

# Configure your AI provider (choose one)
export EXAAI_LLM="openai/gpt-5"
export LLM_API_KEY="your-openai-key"

# Option: Anthropic
# export EXAAI_LLM="anthropic/claude-sonnet-4-5"
# Option: OpenRouter
# export EXAAI_LLM="openrouter/openai/gpt-5"
# export LLM_API_KEY="your-openrouter-key"
# export LLM_API_BASE="https://openrouter.ai/api/v1"
# Option: Ollama (local models)
# export EXAAI_LLM="ollama/llama3"
# export LLM_API_BASE="http://localhost:11434"

# Run your first assessment (prompt modules auto-detected)
exaai --target https://your-app.com
```

The first run pulls the sandbox Docker image automatically. Results are saved to `exaai_runs/<run-name>`.

---

## Usage

```bash
# Local codebase
exaai --target ./app-directory

# GitHub repository review
exaai --target https://github.com/org/repo

# Black-box web assessment
exaai --target https://your-app.com

# Multi-target
exaai -t https://github.com/org/app -t https://your-app.com

# Explicit modules (overrides auto-detection)
exaai --target https://api.example.com --prompt-modules graphql_security,waf_bypass

# Grey-box authenticated testing
exaai --target https://your-app.com --instruction "Perform authenticated testing using provided credentials and identify authorization flaws"

# Headless / CI mode
exaai -n --target https://your-app.com

# Interactive TUI
exaai tui
```

Smart auto-loading resolves modules from the target when `--prompt-modules` is not set, for example GraphQL endpoints, WebSocket endpoints, OAuth/OIDC flows, and subdomain enumeration.

### Configuration

```bash
export EXAAI_LLM="openai/gpt-5"        # required
export LLM_API_KEY="your-api-key"      # required for hosted providers
export LLM_API_BASE="your-api-base"    # for local / compatible endpoints
export EXAAI_LIGHTWEIGHT_MODE=true     # reduced token consumption
export EXAAI_MAX_SCAN_TOKENS=2000000   # per-scan token budget
export EXAAI_TOOL_TIMEOUT=120          # per-tool timeout (seconds)
export EXAAI_TARGETS="https://your-app.com"  # enforced target scope
```

Recommended models: OpenAI GPT-5 (`openai/gpt-5`), Anthropic Claude Sonnet 4.5 (`anthropic/claude-sonnet-4-5`), Google Gemini (`gemini/gemini-2.0-flash`).

### CI/CD (GitHub Actions)

```yaml
name: exaai-security-test
on:
  pull_request:
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install ExaAiAgent
        run: curl -sSL https://raw.githubusercontent.com/hleliofficiel/ExaAiAgent/main/install.sh | bash
      - name: Run ExaAiAgent
        env:
          EXAAI_LLM: ${{ secrets.EXAAI_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: exaai -n -t ./
```

---

## Security modules

| Module | Description |
|---|---|
| `sql_injection` | SQL / NoSQL injection |
| `xss` | Cross-site scripting |
| `ssrf` | Server-side request forgery |
| `xxe` | XML external entity |
| `rce` | Remote code execution |
| `idor` | Insecure direct object reference |
| `authentication_jwt` | Auth and JWT flaws |
| `business_logic` | Business-logic flaws |
| `csrf` | Cross-site request forgery |
| `race_condition` | Race-condition exploits |
| `graphql_security` | GraphQL-specific attacks |
| `websocket_security` | WebSocket vulnerabilities |
| `oauth_oidc` | OAuth2 / OIDC flaws |
| `waf_bypass` | WAF bypass techniques |
| `subdomain_takeover` | Subdomain takeover |
| `prompt_injection` | AI / LLM prompt injection |
| `kubernetes_security` | K8s RBAC and pod-security auditing |
| `subdomain_enumeration` | OSINT subdomain discovery |
| `port_scanning` | Service discovery and port auditing |
| `technology_fingerprinting` | Web technology identification |

Full vulnerability coverage also includes NoSQL and command injection, GraphQL injection, deserialization flaws, prototype pollution, DOM vulnerabilities, workflow manipulation, session management, CSWSH and WebSocket message injection, subdomain takeover, and misconfigurations. See docs/ for module details.

---

## Architecture

ExaAiAgent combines a multi-agent orchestration engine, a LiteLLM provider abstraction, a Docker sandbox runtime, browser automation, proxy traffic capture, a tool server and registry, security scanners, and CLI/TUI interfaces in the main `exaaiagnt/` package.

Key packages: `agents/` (supervisor, scan modes, shared memory), `grounding/` (EvidenceStore), `knowledge/` (pinned CVE KB), `intelligence/` (EPSS/KEV/OSV feeds), `verification/` (pipeline + hardening), `safety/` (TargetScope, command guard, blocklist), `coordination/` (RunState), `planning/` (attack graph), `validation/` (conf-v1), `reporting/` (SARIF/CSV/HTML), `tools/` (78 registered tools + wrappers), `prompts/` (64 modules), and `benchmark/` (Juice Shop / DVWA / WebGoat smoke tasks).

---

## Proposed next features

The following are proposed, not implemented. They are tracked in ROADMAP.md and IMPROVEMENTS.md.

- **v3.1.0 - orchestration:** LangGraph orchestrator with a dedicated Verifier agent; `exaai mcp` MCP shim; ZAP daemon wrapper; Trivy/Grype SARIF and Prowler JSON importers.
- **E2E gate:** scheduled Juice Shop / DVWA / WebGoat end-to-end runs in CI with real LLM providers, with pass/fail thresholds on detection and false-positive rates.
- **CVE sync:** scheduled `sync_cve` against a signed manifest so the pinned KB stays current without manual seed updates; EPSS/KEV refresh in the same job.
- **Resume & persistence:** crash-safe run resume from `exaai_runs/<run>/` state, verified by a kill-and-resume test.
- **Token reduction:** compressor over sliding windows instead of full history, cropped screenshots and page source, and per-module token accounting in reports.
- **Secrets & SBOM depth:** Trivy/Grype SARIF ingestion, Prowler JSON for cloud posture, and SBOM diffing between scans.
- **Dashboard & API auth:** authenticated dashboard and tool-server API (the current API authz module is a first step).
- **Docs & community:** MkDocs site, good-first-issue backlog, and infra-only sponsorship (features are never gated).

---

## Troubleshooting

**LLM connection failed / model not found:** modern models require a recent `litellm`. Update it with `pip install -U litellm`. On externally-managed Linux environments, use a virtual environment (`python3 -m venv venv && source venv/bin/activate`) or `pip install -U litellm --user --break-system-packages`.

---

## Changelog

Full history is in CHANGELOG.md. Latest release: v3.1.1 (see the v3.1.1 table above).

## Contributing

See CONTRIBUTING.md.

## Acknowledgements

ExaAiAgent builds on LiteLLM, Caido, ProjectDiscovery, Playwright, and Textual.

> [!WARNING]
> Only test applications you own or have permission to test. You are responsible for using ExaAiAgent ethically and legally.
