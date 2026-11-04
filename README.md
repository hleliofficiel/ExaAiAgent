<p align="center">
  <img src=".github/logo.png" width="150" alt="ExaAiAgent Logo">
</p>

<h1 align="center">ExaAiAgent</h1>

<h2 align="center">Advanced AI-Powered Cybersecurity Agent for Comprehensive Penetration Testing</h2>

<div align="center">

[![Python](https://img.shields.io/pypi/pyversions/exaai-agent?color=3776AB)](https://pypi.org/project/exaai-agent/)
[![PyPI](https://img.shields.io/pypi/v/exaai-agent?color=10b981)](https://pypi.org/project/exaai-agent/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0.1-00d4ff.svg)]()

</div>

<br>

> [!TIP]
> **v3.0.1 Released!** Evidence-grounded findings, pinned CVE intelligence, independent verification, scoped execution, token budgets, and reproducible reporting.
>
>  **Connect Your Agent:** You can onboard another AI agent by pointing it to the repository skill:
> ```
> Read https://raw.githubusercontent.com/hleliofficiel/ExaAiAgent/main/SKILL.md and follow the instructions to operate ExaAiAgent
> ```

---

## What's New in v3.0.1

- Target scope enforced before tool execution when `EXAAI_TARGETS` is set.
- Agents have token, tool-call, and spawn budgets to prevent unbounded consumption.
- CVE intelligence joins EPSS, CISA KEV, and OSV with provenance; findings require independent verification.
- Unified reports and the deterministic benchmark harness are included.
- New prompt modules: OWASP LLM Top 10 2025, supply-chain/SBOM triage, exceptional-conditions fail-open, grounded CVE verification.
- Node pinned to 22 LTS, CI lint/test/type-check/smoke all green.

### Previous versions (brief history)

| Version | Summary |
|---|---|
| v3.0.0 | Anti-hallucination grounding (`evidence_id` + EvidenceStore), pinned CVE KB, sandbox hardening (127.0.0.1, no ~/.kube mount, no-new-privileges), attack graph planning, conf-v1 validation, reporting v3 (SARIF/CSV/HTML), single-sourced version. |
| v2.3.2 | K8s scanner tool registration fix, run persistence (`exaai_runs/<run>/`), code-quality/lint pass, SKILL.md expansion. |
| v2.2.5 | CI on PRs, import-safe tool server, multi-tool LLM responses, prompt-module merging, TUI target queue, smarter prompt resolution. |
| v2.2.2 - v2.0 | Recon modules (subdomain/port/fingerprint), K8s/Azure/GCP prompt injection, React2Shell CVE detection, auto-discovery, install.sh. |

Details: see CHANGELOG.md, MIGRATION-v3.md, docs/.

---

##  ExaAiAgent Overview

ExaAiAgent is an elite AI-powered cybersecurity agent that acts like a real penetration tester - running your code dynamically, finding vulnerabilities, and validating them through actual proof-of-concepts. Built for developers and security teams who need fast, accurate security testing.

**Key Capabilities:**

-  **Full hacker toolkit** out of the box
-  **Teams of agents** that collaborate and scale
-  **Real validation** with PoCs, not false positives
-  **Developer‑first** CLI with actionable reports
-  **Auto‑fix & reporting** to accelerate remediation
-  **Multi-LLM Support** - OpenAI, Anthropic, Gemini, local models
-  **Cloud & Container Security** testing capabilities
-  **Smart Module Loading** - Auto-detects and loads relevant modules

##  Use Cases

- **Application Security Testing** - Detect and validate critical vulnerabilities
- **Rapid Penetration Testing** - Get pentests done in hours, not weeks
- **Bug Bounty Automation** - Automate research and generate PoCs
- **CI/CD Integration** - Block vulnerabilities before production
- **API Security Testing** - REST, GraphQL, gRPC security analysis
- **Cloud Security** - AWS, Azure, GCP configuration review

---

##  Quick Start

**Prerequisites:**

- Docker (running)
- Python 3.12+
- An LLM provider (OpenAI, Anthropic, OpenRouter, Ollama, or any compatible provider)

### Installation & First Scan

```bash
# Install ExaAiAgent

# Method 1: Automated Script (Recommended)
pip install exaai-agent
# Method 2: pipx
pipx install exaai-agent

# Configure your AI provider (choose one)

# Option 1: OpenAI
export EXAAI_LLM="openai/gpt-5"
export LLM_API_KEY="your-openai-key"

# Option 2: Anthropic
export EXAAI_LLM="anthropic/claude-sonnet-4-5"
export LLM_API_KEY="your-anthropic-key"

# Option 3: OpenRouter (access multiple models)
export EXAAI_LLM="openrouter/openai/gpt-5"
export LLM_API_KEY="your-openrouter-key"
export LLM_API_BASE="https://openrouter.ai/api/v1"

# Option 4: Ollama (local models)
export EXAAI_LLM="ollama/llama3"
export LLM_API_BASE="http://localhost:11434"

# Run your first security assessment (auto-detects modules!)
exaai --target https://your-app.com
```

> [!NOTE]
> First run automatically pulls the sandbox Docker image. Results are saved to `exaai_runs/<run-name>`

---

##  Features

###  Agentic Security Tools

ExaAiAgent agents come equipped with a comprehensive security testing toolkit:

- **Full HTTP Proxy** - Request/response manipulation and analysis; captured traffic exports to HAR (`exaaiagnt/tools/har_io.py`: `import_har`/`export_har`) and records evidence for the grounding gate
- **Proxy linkage** - Tools declare `proxy_required`/`allowed_prompt_modules`/`blocked` in the registry manifest; the executor enforces scope, blocklist, and proxy requirements before execution (`exaaiagnt/tools/registry.py`, `exaaiagnt/tools/proxy_env.py`, `exaaiagnt/tools/executor.py`)
- **Blocklist enforcement** - Blocked paths, modules, and URL segments are denied with `ScopeDecision` evidence from the executor, command guard, and proxy manager (`exaaiagnt/safety/blocklist.py`)
- **Tool manifest** - `get_tool_manifest` / `tools_for_prompt_module` expose per-tool manifest fields for prompt scoping and auditing
- **Browser Automation** - Multi-tab browser for XSS, CSRF, auth flows
- **Browser JS analysis** - Offline DOM XSS, postMessage origin, Service Worker, and JS bundle endpoint/secret extraction (`exaaiagnt/tools/browser_js_analysis.py`: `analyze_browser_js`, `analyze_js_bundle`)
- **Terminal Environments** - Interactive shells for command execution
- **Python Runtime** - Custom exploit development and validation
- **Reconnaissance** - Automated OSINT and attack surface mapping
- **Code Analysis** - Static and dynamic analysis capabilities
- **API Fuzzing** - Advanced REST/GraphQL API testing
- **Coordination** - Persistent `RunState` save/load/resume, task queue with bounded depth, token/cost budgets, and heartbeat-vs-activity stuck detection, exposed as `coordination_*` tools (`exaaiagnt/coordination/state.py`, `exaaiagnt/tools/coordination/`)
- **LLM/MCP/RAG tests** - Offline OWASP LLM Top 10 (2025) checkers: prompt-injection detection, system-prompt/secret leak detection, MCP server manifest audit, RAG provenance and cross-tenant checks, exposed as `audit_mcp_manifest_tool`, `detect_prompt_injection_tool`, `evaluate_rag_corpus_tool`, `harden_finding_text_tool` (`exaaiagnt/llm_tests/mcp_rag.py`, `exaaiagnt/tools/llm_tests/`)

###  Comprehensive Vulnerability Detection

ExaAiAgent identifies and validates a wide range of security vulnerabilities:

| Category | Vulnerabilities |
|----------|-----------------|
| **Access Control** | IDOR, privilege escalation, auth bypass |
| **Injection** | SQL, NoSQL, Command, GraphQL injection |
| **Server-Side** | SSRF, XXE, deserialization flaws |
| **Client-Side** | XSS, prototype pollution, DOM vulnerabilities |
| **Business Logic** | Race conditions, workflow manipulation |
| **Authentication** | JWT vulnerabilities, OAuth/OIDC flaws, session management |
| **WebSocket** | CSWSH, message injection, DoS |
| **Infrastructure** | Subdomain takeover, misconfigurations |
| **WAF Bypass** | Encoding, smuggling, header manipulation |

###  Graph of Agents

Advanced multi-agent orchestration for comprehensive security testing:

- **Distributed Workflows** - Specialized agents for different attacks
- **Scalable Testing** - Parallel execution for fast coverage
- **Dynamic Coordination** - Agents collaborate and share discoveries
- **Persistent coordination state** - `RunState` save/load/resume, bounded task queue, budget guard, and stuck detection via `coordination_*` tools (`exaaiagnt/coordination/state.py`)
- **Verification hardening** - `verify_finding` downgrades a would-be `confirmed` finding to `suspected` on high-severity injection, secret leak, or cross-tenant RAG evidence; reports carry additive `hardening` metadata
- **MCP manifest audit** - `audit_mcp_manifest_tool` audits an MCP server manifest for broad permissions, dangerous tools, injection, and missing auth/timeout

---

##  Usage Examples

### Basic Usage

```bash
# Scan a local codebase
exaai --target ./app-directory

# Security review of a GitHub repository
exaai --target https://github.com/org/repo

# Black-box web application assessment
exaai --target https://your-app.com
```

### Smart Auto-Loading (New in v2.0!)

```bash
# GraphQL endpoint - auto-loads graphql_security
exaai --target https://api.example.com/graphql

# WebSocket - auto-loads websocket_security
exaai --target wss://chat.example.com/socket

# OAuth endpoint - auto-loads oauth_oidc
exaai --target https://auth.example.com/oauth/authorize

# Subdomain recon - auto-loads subdomain_takeover
exaai --target example.com --instruction "enumerate subdomains"
```

### Advanced Testing Scenarios

```bash
# Grey-box authenticated testing
exaai --target https://your-app.com --instruction "Perform authenticated testing using credentials: user:pass"

# Multi-target testing (source code + deployed app)
exaai -t https://github.com/org/app -t https://your-app.com

# With specific modules (overrides auto-detection)
exaai --target https://api.example.com --prompt-modules graphql_security,waf_bypass

# Lightweight mode (reduced token consumption)
export EXAAI_LIGHTWEIGHT_MODE=true
exaai --target https://example.com --instruction "quick security scan"
```

###  Headless Mode

Run ExaAiAgent programmatically without interactive UI:

```bash
exaai -n --target https://your-app.com
```

###  CI/CD (GitHub Actions)

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

###  Configuration

```bash
# Required
export EXAAI_LLM="openai/gpt-5"
export LLM_API_KEY="your-api-key"

# Optional - Performance tuning
export EXAAI_LIGHTWEIGHT_MODE=true    # Reduced token consumption
export EXAAI_MAX_TOKENS=2048          # Max output tokens
export LLM_API_BASE="your-api-base"   # For local models
export PERPLEXITY_API_KEY="key"       # For search capabilities
```

**Recommended Models:**

- OpenAI GPT-5 (`openai/gpt-5`)
- Anthropic Claude Sonnet 4.5 (`anthropic/claude-sonnet-4-5`)
- Google Gemini 3.0 (`gemini/gemini-2.0-flash`)

---

##  Available Security Modules

### Vulnerability Modules

| Module | Description |
|--------|-------------|
| `sql_injection` | SQL/NoSQL injection testing |
| `xss` | Cross-site scripting attacks |
| `ssrf` | Server-side request forgery |
| `xxe` | XML external entity attacks |
| `rce` | Remote code execution |
| `idor` | Insecure direct object reference |
| `authentication_jwt` | Auth & JWT vulnerabilities |
| `business_logic` | Business logic flaws |
| `csrf` | Cross-site request forgery |
| `race_condition` | Race condition exploits |
| `graphql_security` | GraphQL-specific attacks |
| `websocket_security` | WebSocket vulnerabilities |
| `oauth_oidc` | OAuth2/OIDC flaws |
| `waf_bypass` | WAF bypass techniques |
| `subdomain_takeover` | Subdomain takeover |
| `prompt_injection` | AI/LLM prompt injection attacks |
| `kubernetes_security` | **NEW!** K8s RBAC & Pod Security auditing |
| `subdomain_enumeration` | **NEW!** OSINT-based subdomain discovery |
| `port_scanning` | **NEW!** Service discovery & port auditing |
| `technology_fingerprinting` | **NEW!** Web tech stack identification |

---

## Changelog

Full history is in CHANGELOG.md. Latest release: v3.0.1 (see "What's New in v3.0.1" above).

---

##  Troubleshooting

###  Troubleshooting

#### Problem: "LLM Connection Failed" or Model Not Found
Modern models (like `gemini-3-pro-preview`) require the latest version of `litellm` to be recognized correctly.

**Solution: Update LiteLLM**
```bash
pip install -U litellm
```

**Linux/Debian Users (Externally Managed Environment):**
If you encounter permission errors or "externally-managed-environment", you may need to use a virtual environment (`venv`) or force a user install:

```bash
# Option 1: Virtual Environment (Recommended for Servers)
python3 -m venv venv
source venv/bin/activate
pip install exaai-agent

# Option 2: Force User Install
pip install -U litellm --user --break-system-packages
```

---

##  Contributing

We welcome contributions! Check out our [Contributing Guide](CONTRIBUTING.md).

##  Support the Project

**Love ExaAiAgent?** Give us a  on GitHub!

##  Acknowledgements

ExaAiAgent builds on incredible open-source projects like [LiteLLM](https://github.com/BerriAI/litellm), [Caido](https://github.com/caido/caido), [ProjectDiscovery](https://github.com/projectdiscovery), [Playwright](https://github.com/microsoft/playwright), and [Textual](https://github.com/Textualize/textual).

> [!WARNING]
> Only test apps you own or have permission to test. You are responsible for using ExaAiAgent ethically and legally.
