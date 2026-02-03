<p align="center">
  <img src=".github/logo.png" width="150" alt="ExaAiAgent Logo">
</p>

<h1 align="center">ExaAiAgent</h1>

<h2 align="center">Advanced AI-Powered Cybersecurity Agent for Comprehensive Penetration Testing</h2>

<div align="center">

[![Python](https://img.shields.io/pypi/pyversions/exaai-agent?color=3776AB)](https://pypi.org/project/exaai-agent/)
[![PyPI](https://img.shields.io/pypi/v/exaai-agent?color=10b981)](https://pypi.org/project/exaai-agent/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.1.2-00d4ff.svg)]()

</div>

<br>

> [!TIP]
> **🚀 v2.1.2 Released!** Now supports **AI Agent Integration (OpenClaw)**, Kubernetes Security, Azure/GCP modules, and Prompt Injection detection.
>
> 🤖 **Connect Your Agent:** You can now control ExaAiAgent via any AI agent (OpenClaw, etc).
> Just send this command to your agent:
> ```
> Read https://raw.githubusercontent.com/hleliofficiel/ExaAiAgent/main/SKILL.md and follow the instructions to join ExaAiAgent
> ```

---

## 🔥 What's New in v2.1.2

### 🤖 AI Agent Integration (OpenClaw)

Seamlessly integrate ExaAiAgent with your AI workforce:

- **Agent Control**: Control scans via OpenClaw or any agent framework
- **Auto-Discovery**: Agents can read `SKILL.md` to self-onboard
- **Output Optimization**: Tools now output cleaner data (no ANSI codes) for LLM consumption

### ⚓ Kubernetes & Cloud Security (Updated)

Expanded coverage for cloud-native infrastructure:

- **Kubernetes**: Deep RBAC auditing, Pod Security Standards (PSS), Network Policy checks
- **Azure**: Blob Storage, Entra ID (Azure AD), Key Vault auditing
- **GCP**: Cloud Storage, IAM, Service Account key leaks
- **Prompt Injection**: Dedicated scanner for AI/LLM applications

### 🛡️ Smart Security Tools

| Tool | Capability |
|------|------------|
| **Smart Fuzzer** | Thread-safe, context-aware fuzzing with rate limiting |
| **Response Analyzer** | SQL errors, stack traces, sensitive data detection |
| **Vuln Validator** | PoC generation with false positive reduction |
| **WAF Bypass** | Multi-layer bypass for Cloudflare, Akamai, AWS WAF |

### ⚡ CLI & Stability

- **Thread-Safety**: Fixed race conditions in async scans
- **Resource Management**: Auto-shutdown and cleanup of background processes
- **Installation**: Robust `install.sh` for Linux/macOS (bash/zsh/fish)

```bash
# New install script
curl -sSL https://raw.githubusercontent.com/hleliofficiel/ExaAiAgent/main/install.sh | bash
```

---

## 🔥 ExaAiAgent Overview

ExaAiAgent is an elite AI-powered cybersecurity agent that acts like a real penetration tester - running your code dynamically, finding vulnerabilities, and validating them through actual proof-of-concepts. Built for developers and security teams who need fast, accurate security testing.

**Key Capabilities:**

- 🔧 **Full hacker toolkit** out of the box
- 🤝 **Teams of agents** that collaborate and scale
- ✅ **Real validation** with PoCs, not false positives
- 💻 **Developer‑first** CLI with actionable reports
- 🔄 **Auto‑fix & reporting** to accelerate remediation
- 🧠 **Multi-LLM Support** - OpenAI, Anthropic, Gemini, local models
- 🌐 **Cloud & Container Security** testing capabilities
- 🚀 **Smart Module Loading** - Auto-detects and loads relevant modules

## 🎯 Use Cases

- **Application Security Testing** - Detect and validate critical vulnerabilities
- **Rapid Penetration Testing** - Get pentests done in hours, not weeks
- **Bug Bounty Automation** - Automate research and generate PoCs
- **CI/CD Integration** - Block vulnerabilities before production
- **API Security Testing** - REST, GraphQL, gRPC security analysis
- **Cloud Security** - AWS, Azure, GCP configuration review

---

## 🚀 Quick Start

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
export EXAAI_LLM="openrouter/auto"
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

## ✨ Features

### 🛠️ Agentic Security Tools

ExaAiAgent agents come equipped with a comprehensive security testing toolkit:

- **Full HTTP Proxy** - Request/response manipulation and analysis
- **Browser Automation** - Multi-tab browser for XSS, CSRF, auth flows
- **Terminal Environments** - Interactive shells for command execution
- **Python Runtime** - Custom exploit development and validation
- **Reconnaissance** - Automated OSINT and attack surface mapping
- **Code Analysis** - Static and dynamic analysis capabilities
- **API Fuzzing** - Advanced REST/GraphQL API testing

### 🎯 Comprehensive Vulnerability Detection

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

### 🕸️ Graph of Agents

Advanced multi-agent orchestration for comprehensive security testing:

- **Distributed Workflows** - Specialized agents for different attacks
- **Scalable Testing** - Parallel execution for fast coverage
- **Dynamic Coordination** - Agents collaborate and share discoveries

---

## 💻 Usage Examples

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
exaai --target https://api.example.com --prompt-modules graphql_security waf_bypass

# Lightweight mode (reduced token consumption)
export EXAAI_LIGHTWEIGHT_MODE=true
exaai --target https://example.com --instruction "quick security scan"
```

### 🤖 Headless Mode

Run ExaAiAgent programmatically without interactive UI:

```bash
exaai -n --target https://your-app.com
```

### 🔄 CI/CD (GitHub Actions)

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

### ⚙️ Configuration

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
- Google Gemini 2.0 (`gemini/gemini-2.0-flash`)

---

## 📦 Available Security Modules

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

---

## 🆕 Changelog

### v2.1.2 (Latest)
- **AI Agent Integration**: OpenClaw/Agent compatibility
- **Stability Fixes**: ToolManager thread-safety, Resource cleanup
- **DevEx**: New `install.sh` script, improved logging

### v2.1.0
- **New Modules**: K8s, Azure, GCP, Prompt Injection
- **React2Shell**: CVE-2025-55182 detection
- **Auto-Discovery**: Improved target detection

---

## 🛠️ Troubleshooting

### Problem: "LLM Connection Failed" or New Models (Gemini 3, etc.)
If you encounter errors connecting to newer models (like `gemini/gemini-3-pro-preview`), you may need to update the `litellm` library.

**Linux/Debian Users (Externally Managed Environment):**
If you see an error about "externally-managed-environment", run this command to force the update in your user space:

```bash
pip install -U litellm --user --break-system-packages
```

---

## 🤝 Contributing

We welcome contributions! Check out our [Contributing Guide](CONTRIBUTING.md).

## 🌟 Support the Project

**Love ExaAiAgent?** Give us a ⭐ on GitHub!

## 🙏 Acknowledgements

ExaAiAgent builds on incredible open-source projects like [LiteLLM](https://github.com/BerriAI/litellm), [Caido](https://github.com/caido/caido), [ProjectDiscovery](https://github.com/projectdiscovery), [Playwright](https://github.com/microsoft/playwright), and [Textual](https://github.com/Textualize/textual).

> [!WARNING]
> Only test apps you own or have permission to test. You are responsible for using ExaAiAgent ethically and legally.

</div>
