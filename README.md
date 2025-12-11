<p align="center">
  <img src=".github/logo.png" width="150" alt="ExaAiAgent Logo">
</p>

<h1 align="center">ExaAiAgent</h1>

<h2 align="center">Advanced AI-Powered Cybersecurity Agent for Comprehensive Penetration Testing</h2>

<div align="center">

[![Python](https://img.shields.io/pypi/pyversions/exaai-agent?color=3776AB)](https://pypi.org/project/exaai-agent/)
[![PyPI](https://img.shields.io/pypi/v/exaai-agent?color=10b981)](https://pypi.org/project/exaai-agent/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.4-00d4ff.svg)]()

</div>

<br>

> [!TIP]
> **v2.0.4 Released!** Agent Supervisor with Self-Healing, WAF Detection & Bypass, Scan Modes (Stealth/Aggressive), Shared Memory Bus, and 80% Token Reduction!

---

## 🔥 What's New

| Feature | Description |
|---------|-------------|
| 🛡️ **Agent Supervisor** | Self-healing with heartbeat, auto-recovery, priority levels |
| 🧠 **Shared Memory** | Inter-agent coordination, URL deduplication |
| 🎭 **Scan Modes** | 🥷 Stealth (10/min) • ⚖️ Standard (60/min) • 🔥 Aggressive (300/min) |
| 🔓 **WAF Bypass** | Cloudflare, Akamai, Imperva detection & bypass |
| ⚡ **80% Less Tokens** | Smart output processing, URL prioritization |
| ✨ **Auto-Module Loading** | GraphQL, WebSocket, OAuth auto-detected |
| 🎨 **Fresh Logo** | Block-style ASCII with gradient colors |

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
exaaiagnt --target https://your-app.com
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
exaaiagnt --target ./app-directory

# Security review of a GitHub repository
exaaiagnt --target https://github.com/org/repo

# Black-box web application assessment
exaaiagnt --target https://your-app.com
```

### Smart Auto-Loading (New in v2.0!)

```bash
# GraphQL endpoint - auto-loads graphql_security
exaaiagnt --target https://api.example.com/graphql

# WebSocket - auto-loads websocket_security
exaaiagnt --target wss://chat.example.com/socket

# OAuth endpoint - auto-loads oauth_oidc
exaaiagnt --target https://auth.example.com/oauth/authorize

# Subdomain recon - auto-loads subdomain_takeover
exaaiagnt --target example.com --instruction "enumerate subdomains"
```

### Advanced Testing Scenarios

```bash
# Grey-box authenticated testing
exaaiagnt --target https://your-app.com --instruction "Perform authenticated testing using credentials: user:pass"

# Multi-target testing (source code + deployed app)
exaaiagnt -t https://github.com/org/app -t https://your-app.com

# With specific modules (overrides auto-detection)
exaaiagnt --target https://api.example.com --prompt-modules graphql_security waf_bypass

# Lightweight mode (reduced token consumption)
export EXAAI_LIGHTWEIGHT_MODE=true
exaaiagnt --target https://example.com --instruction "quick security scan"
```

### 🤖 Headless Mode

Run ExaAiAgent programmatically without interactive UI:

```bash
exaaiagnt -n --target https://your-app.com
```

### 🔄 CI/CD (GitHub Actions)

```yaml
name: exaaiagnt-security-test

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install ExaAiAgent
        run: pipx install exaai-agent

      - name: Run ExaAiAgent
        env:
          EXAAI_LLM: ${{ secrets.EXAAI_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: exaaiagnt -n -t ./
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

---

## 🆕 Changelog

### v2.0.4 (Latest)

- 🛡️ **Agent Supervisor** - Self-healing with heartbeat, timeout detection, auto-recovery
- 🧠 **Shared Memory Bus** - Inter-agent communication, URL deduplication
- 🎭 **Scan Modes** - Stealth (10 req/min), Standard (60), Aggressive (300)
- 🔓 **WAF Bypass** - Cloudflare, Akamai, Imperva detection & bypass techniques
- ⚡ **80% Token Reduction** - Smart output processing, URL prioritization
- 🎯 **Priority Levels** - HIGH/MEDIUM/LOW agent scheduling
- 💰 **Token Budget** - Per-agent limits with enforcement
- 🎨 **Fresh Logo** - Block-style ASCII with gradient colors

### v2.0.0

- ✨ **Smart Auto-Module Loading** - Automatically detects target type
- ⚡ **Token Optimization** - Lightweight mode & task scaling
- 🛡️ **5 New Security Modules** - GraphQL, WebSocket, OAuth, WAF, Subdomain
- 🎨 **New UI/Branding** - Fresh ExaAi logo with Cyan/Purple theme
- 📊 **Improved Performance** - Reduced unnecessary LLM calls

### v1.0.0

- Multi-LLM Load Balancing
- Enhanced Context Management
- Specialized Agents
- Advanced Prompts
- Improved Reporting

---

## 🤝 Contributing

We love contributions! Here's how you can help:

<table>
<tr>
<td>🐛 <b>Report Bugs</b></td>
<td>Found a bug? <a href="https://github.com/exaai/exaai-agent/issues/new?template=bug_report.md">Open an issue</a></td>
</tr>
<tr>
<td>💡 <b>Feature Requests</b></td>
<td>Have an idea? <a href="https://github.com/exaai/exaai-agent/issues/new?template=feature_request.md">Suggest a feature</a></td>
</tr>
<tr>
<td>🔧 <b>Pull Requests</b></td>
<td>Want to contribute code? Check our <a href="CONTRIBUTING.md">Contributing Guide</a></td>
</tr>
<tr>
<td>📖 <b>Documentation</b></td>
<td>Help improve our docs and examples</td>
</tr>
</table>

---

## 🌟 Support the Project

<p align="center">
  <b>Love ExaAiAgent?</b> Show your support!
</p>

<p align="center">
  <a href="https://github.com/exaai/exaai-agent">⭐ Star on GitHub</a> •
  <a href="https://twitter.com/exaaiagent">🐦 Follow on Twitter</a> •
  <a href="https://discord.gg/exaai">💬 Join Discord</a>
</p>

---

## 📜 License

This project is licensed under the **Apache 2.0 License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

ExaAiAgent is built on the shoulders of giants:

| Project | Usage |
|---------|-------|
| [LiteLLM](https://github.com/BerriAI/litellm) | Multi-LLM Support |
| [Playwright](https://github.com/microsoft/playwright) | Browser Automation |
| [ProjectDiscovery](https://github.com/projectdiscovery) | Security Tools |
| [Textual](https://github.com/Textualize/textual) | TUI Framework |
| [Rich](https://github.com/Textualize/rich) | Terminal Output |

---

## ⚠️ Disclaimer

> [!WARNING]
> **Legal Notice**: Only use ExaAiAgent on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. You are solely responsible for your actions.

---

<p align="center">
  <b>Built with ❤️ by the ExaAi Team</b>
  <br>
  <sub>Making cybersecurity accessible to everyone</sub>
</p>

<p align="center">
  <a href="https://exaai.io">🌐 Website</a> •
  <a href="https://docs.exaai.io">📚 Docs</a> •
  <a href="https://github.com/exaai/exaai-agent">💻 GitHub</a>
</p>

</div>
