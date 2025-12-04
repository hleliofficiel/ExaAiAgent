<p align="center">
  <img src=".github/logo.png" width="150" alt="ExaaiAgnt Logo">
</p>

<h1 align="center">ExaaiAgnt</h1>

<h2 align="center">Advanced AI Security Agent for Comprehensive Penetration Testing</h2>

<div align="center">

[![Python](https://img.shields.io/pypi/pyversions/exaai-agent?color=3776AB)](https://pypi.org/project/exaai-agent/)
[![PyPI](https://img.shields.io/pypi/v/exaai-agent?color=10b981)](https://pypi.org/project/exaai-agent/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

</div>

<br>

> [!TIP]
> **New!** ExaaiAgnt now integrates seamlessly with GitHub Actions and CI/CD pipelines. Automatically scan for vulnerabilities on every pull request and block insecure code before it reaches production!

---

## 🔥 ExaaiAgnt Overview

ExaaiAgnt is an elite AI-powered cybersecurity agent that acts like a real penetration tester - running your code dynamically, finding vulnerabilities, and validating them through actual proof-of-concepts. Built for developers and security teams who need fast, accurate security testing.

**Key Capabilities:**

- 🔧 **Full hacker toolkit** out of the box
- 🤝 **Teams of agents** that collaborate and scale
- ✅ **Real validation** with PoCs, not false positives
- 💻 **Developer‑first** CLI with actionable reports
- 🔄 **Auto‑fix & reporting** to accelerate remediation
- 🧠 **Multi-LLM Support** - OpenAI, Anthropic, Gemini, local models
- 🌐 **Cloud & Container Security** testing capabilities

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
# Install ExaaiAgnt
pipx install exaai-agent

# Configure your AI provider (choose one)

# Option 1: OpenAI
export EXAAI_LLM="openai/gpt-5"
export LLM_API_KEY="your-openai-key"

# Option 2: Anthropic
export EXAAI_LLM="anthropic/claude-sonnet-4-5"
export LLM_API_KEY="your-anthropic-key"

# Option 3: OpenRouter (access multiple models)
export EXAAI_LLM="openrouter/auto"  # or specific model like "openrouter/openai/gpt-4"
export LLM_API_KEY="your-openrouter-key"
export LLM_API_BASE="https://openrouter.ai/api/v1"

# Option 4: Ollama (local models)
export EXAAI_LLM="ollama/llama3"
export LLM_API_BASE="http://localhost:11434"

# Option 5: LMStudio (local models)
export EXAAI_LLM="openai/local-model"
export LLM_API_BASE="http://localhost:1234/v1"

# Run your first security assessment
exaaiagnt --target ./app-directory
```

> [!NOTE]
> First run automatically pulls the sandbox Docker image. Results are saved to `exaai_runs/<run-name>`

---

## ✨ Features

### 🛠️ Agentic Security Tools

ExaaiAgnt agents come equipped with a comprehensive security testing toolkit:

- **Full HTTP Proxy** - Request/response manipulation and analysis
- **Browser Automation** - Multi-tab browser for XSS, CSRF, auth flows
- **Terminal Environments** - Interactive shells for command execution
- **Python Runtime** - Custom exploit development and validation
- **Reconnaissance** - Automated OSINT and attack surface mapping
- **Code Analysis** - Static and dynamic analysis capabilities
- **API Fuzzing** - Advanced REST/GraphQL API testing

### 🎯 Comprehensive Vulnerability Detection

ExaaiAgnt identifies and validates a wide range of security vulnerabilities:

- **Access Control** - IDOR, privilege escalation, auth bypass
- **Injection Attacks** - SQL, NoSQL, command injection
- **Server-Side** - SSRF, XXE, deserialization flaws
- **Client-Side** - XSS, prototype pollution, DOM vulnerabilities
- **Business Logic** - Race conditions, workflow manipulation
- **Authentication** - JWT vulnerabilities, session management
- **Infrastructure** - Misconfigurations, exposed services
- **Cloud Security** - AWS/Azure/GCP misconfigurations

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

### Advanced Testing Scenarios

```bash
# Grey-box authenticated testing
exaaiagnt --target https://your-app.com --instruction "Perform authenticated testing using credentials: user:pass"

# Multi-target testing (source code + deployed app)
exaaiagnt -t https://github.com/org/app -t https://your-app.com

# Focused testing with custom instructions
exaaiagnt --target api.your-app.com --instruction "Focus on business logic flaws and IDOR vulnerabilities"

# Instructions from file
exaaiagnt --target api.your-app.com --instruction ./instruction.md
```

### 🤖 Headless Mode

Run ExaaiAgnt programmatically without interactive UI:

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

      - name: Install ExaaiAgnt
        run: pipx install exaai-agent

      - name: Run ExaaiAgnt
        env:
          EXAAI_LLM: ${{ secrets.EXAAI_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: exaaiagnt -n -t ./
```

### ⚙️ Configuration

```bash
export EXAAI_LLM="openai/gpt-5"
export LLM_API_KEY="your-api-key"

# Optional
export LLM_API_BASE="your-api-base-url"  # for local models (Ollama, LMStudio)
export PERPLEXITY_API_KEY="your-api-key"  # for search capabilities
```

**Recommended Models:**

- OpenAI GPT-5 (`openai/gpt-5`)
- Anthropic Claude Sonnet 4.5 (`anthropic/claude-sonnet-4-5`)
- Google Gemini 2.0 (`gemini/gemini-2.0-flash`)

---

## 🆕 New Features in v1.0

- **Multi-LLM Load Balancing** - Automatic failover between models
- **Enhanced Context Management** - Better memory and conversation handling
- **Specialized Agents** - API, Cloud, Mobile, Container security experts
- **Advanced Prompts** - New vulnerability modules for emerging threats
- **Improved Reporting** - Detailed PoC documentation and remediation guides

---

## 🤝 Contributing

We welcome contributions! Check out our [Contributing Guide](CONTRIBUTING.md).

## 🌟 Support the Project

**Love ExaaiAgnt?** Give us a ⭐ on GitHub!

## 🙏 Acknowledgements

ExaaiAgnt builds on incredible open-source projects like [LiteLLM](https://github.com/BerriAI/litellm), [Caido](https://github.com/caido/caido), [ProjectDiscovery](https://github.com/projectdiscovery), [Playwright](https://github.com/microsoft/playwright), and [Textual](https://github.com/Textualize/textual).

> [!WARNING]
> Only test apps you own or have permission to test. You are responsible for using ExaaiAgnt ethically and legally.

</div>
