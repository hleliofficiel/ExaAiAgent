---
name: ExaAiAgent
description: "AI-powered penetration testing framework. Run security scans on websites, APIs, repos, and cloud infrastructure. Use `exaai` CLI or TUI for vuln detection, pentesting automation, and PoC generation."
homepage: https://github.com/hleliofficiel/ExaAiAgent
metadata:
  {
    "openclaw":
      {
        "emoji": "🛡️",
        "requires": { "bins": ["exaai", "docker"] },
        "install":
          [
            {
              "id": "pipx",
              "kind": "shell",
              "command": "pipx install exaai-agent",
              "bins": ["exaai"],
              "label": "Install ExaAiAgent (pipx)",
            },
            {
              "id": "pip",
              "kind": "shell",
              "command": "pip install exaai-agent",
              "bins": ["exaai"],
              "label": "Install ExaAiAgent (pip)",
            },
          ],
      },
  }
---

# ExaAiAgent Skill 🛡️

Run AI-powered penetration tests from your agent. ExaAiAgent acts like a real pentester - finding vulnerabilities, generating PoCs, and providing remediation advice.

---

## 📚 Self-Learning Protocol

When working with ExaAiAgent, **ALWAYS** follow this discovery sequence:

### 1. Explore the Codebase
```bash
# Find all Python files
find /path/to/ExaAiAgent -type f -name "*.py" | head -50

# List all directories
ls -la /path/to/ExaAiAgent/
ls -la /path/to/ExaAiAgent/exaaiagnt/

# Find all prompts/modules
find /path/to/ExaAiAgent -name "*.jinja" -o -name "*.py" | grep -E "(prompts|tools)"
```

### 2. Read the Documentation
```bash
# Main documentation
cat /path/to/ExaAiAgent/README.md

# Contributing guide
cat /path/to/ExaAiAgent/CONTRIBUTING.md

# Check for inline docs
head -100 /path/to/ExaAiAgent/exaaiagnt/tools/__init__.py
```

### 3. Understand the Structure
```
ExaAiAgent/
├── exaaiagnt/
│   ├── agents/          # Agent orchestration
│   ├── interface/       # CLI/TUI interfaces
│   ├── llm/             # LLM integrations
│   ├── prompts/         # Jinja2 prompt templates
│   │   ├── agent/       # Agent behavior prompts
│   │   └── vulnerabilities/  # Vuln-specific prompts
│   ├── runtime/         # Sandbox runtime
│   ├── tools/           # Security tools
│   │   ├── browser/     # Browser automation
│   │   ├── proxy/       # HTTP proxy
│   │   ├── python/      # Python execution
│   │   ├── prompt_injection/  # AI security testing
│   │   └── ...
│   └── telemetry/       # Usage analytics
├── tests/               # Test suite
├── containers/          # Docker configs
├── README.md            # Main docs
├── CONTRIBUTING.md      # Contribution guide
└── pyproject.toml       # Dependencies
```

---

## 🚀 Interface Modes

### Option 1: Text User Interface (TUI) - Interactive
Use when the user wants to **visually interact** with the scanning process:

```bash
# Launch interactive TUI
exaai tui

# Or directly with target
exaai --target https://example.com
```

**TUI Features:**
- Real-time scan progress visualization
- Interactive module selection
- Live vulnerability discovery feed
- Report navigation

**⚠️ Note for Agents:** TUI requires a TTY. If running headless/automated, use CLI mode instead.

### Option 2: CLI Headless - Automation
Use for **automated scans** and **agent workflows**:

```bash
# Headless mode (RECOMMENDED for agents)
exaai -n --target https://example.com

# With custom instructions
exaai -n --target https://api.example.com --instruction "Focus on authentication and API security"

# Specific modules only
exaai -n --target https://example.com --prompt-modules sql_injection,xss,ssrf
```

**CLI Flags:**
| Flag | Description |
|------|-------------|
| `-n`, `--headless` | Run without TUI (required for automation) |
| `-t`, `--target` | Target URL, repo, or path |
| `--instruction` | Custom scanning instructions |
| `--prompt-modules` | Specific modules to load |
| `--version` | Show version |

---

## 🔧 LLM Provider Configuration

### First-Time Setup - Ask the User

When a user requests a scan and LLM is not configured, **ask them**:

```
🛡️ ExaAiAgent needs an AI model to run security analysis.

Which provider would you like to use?

1. **OpenAI** - GPT-4 / GPT-5 (best quality)
2. **Anthropic** - Claude Sonnet 4.5 (great for code)
3. **OpenRouter** - Access multiple models
4. **Ollama** - Local models (no API key)
5. **Google Gemini** - Fast and capable
6. **Other** - Custom provider

Reply with a number or provider name.
```

### After User Chooses Provider

**If they need to provide an API key:**
```
Please send your API key for [Provider].
Example: sk-xxxxxxxxxxxx

💡 Tip: You can also provide a custom base URL if using a self-hosted or proxy endpoint.
```

**If using custom/unknown provider:**
```
Please provide:
1. Model string (e.g., `custom/model-name`)
2. API key
3. Base URL (e.g., `https://your-api.com/v1`)
```

### Configuration Commands

```bash
# Option 1: OpenAI
export EXAAI_LLM="openai/gpt-5"
export LLM_API_KEY="sk-xxxxxxxxxxxx"

# Option 2: Anthropic
export EXAAI_LLM="anthropic/claude-sonnet-4-5"
export LLM_API_KEY="sk-ant-xxxxxxxxxxxx"

# Option 3: OpenRouter (access multiple models)
export EXAAI_LLM="openrouter/auto"
export LLM_API_KEY="sk-or-xxxxxxxxxxxx"
export LLM_API_BASE="https://openrouter.ai/api/v1"

# Option 4: Ollama (local models - NO API key needed!)
export EXAAI_LLM="ollama/llama3"
export LLM_API_BASE="http://localhost:11434"

# Option 5: Google Gemini
export EXAAI_LLM="gemini/gemini-2.0-flash"
export LLM_API_KEY="your-google-api-key"

# Option 6: Custom Provider (any OpenAI-compatible API)
export EXAAI_LLM="custom/your-model"
export LLM_API_KEY="your-key"
export LLM_API_BASE="https://your-custom-endpoint.com/v1"
```

### Supported Models Reference

| Provider | Model String | API Key Required | Base URL |
|----------|--------------|------------------|----------|
| OpenAI | `openai/gpt-4`, `openai/gpt-5` | ✅ | Default |
| Anthropic | `anthropic/claude-sonnet-4-5` | ✅ | Default |
| OpenRouter | `openrouter/auto`, `openrouter/model-name` | ✅ | `https://openrouter.ai/api/v1` |
| Ollama | `ollama/llama3`, `ollama/codellama` | ❌ | `http://localhost:11434` |
| Google | `gemini/gemini-2.0-flash` | ✅ | Default |
| Groq | `groq/llama3-70b` | ✅ | `https://api.groq.com/openai/v1` |
| Together | `together/mixtral-8x7b` | ✅ | `https://api.together.xyz/v1` |
| Custom | `custom/your-model` | varies | User-provided |

---

## 📋 Scan Commands

### Basic Scans

```bash
# Web application scan
exaai -n --target https://example.com

# API security assessment
exaai -n --target https://api.example.com/v1

# GitHub repository scan (source code analysis)
exaai -n --target https://github.com/org/repo

# Local codebase scan
exaai -n --target ./path/to/code
```

### Advanced Scans

```bash
# Authenticated testing
exaai -n --target https://app.example.com \
  --instruction "Perform authenticated testing using credentials: user:pass"

# Multi-target testing
exaai -n -t https://github.com/org/app -t https://prod.example.com

# Specific vulnerability focus
exaai -n --target https://example.com \
  --prompt-modules sql_injection,authentication_jwt,idor

# GraphQL API (auto-detected)
exaai -n --target https://api.example.com/graphql

# WebSocket testing (auto-detected)
exaai -n --target wss://chat.example.com/socket

# Cloud infrastructure audit
exaai -n --target aws --prompt-modules cloud_security

# Kubernetes security audit
exaai -n --target kubectl --prompt-modules kubernetes_security
```

### Performance Options

```bash
# Lightweight mode (reduce token consumption)
EXAAI_LIGHTWEIGHT_MODE=true exaai -n --target https://example.com

# Custom max tokens
EXAAI_MAX_TOKENS=2048 exaai -n --target https://example.com
```

---

## 🤖 Agent Workflow

### Step 1: Parse User Request

**User says:** "Scan https://shop.example.com for SQL injection"

**Extract:**
- Target: `https://shop.example.com`
- Focus: `sql_injection`

### Step 2: Verify Prerequisites

```bash
# Check Docker
docker info > /dev/null 2>&1 && echo "✅ Docker OK" || echo "❌ Docker not running"

# Check ExaAiAgent
which exaai && exaai --version

# Check LLM config
[[ -n "$EXAAI_LLM" ]] && echo "✅ LLM: $EXAAI_LLM" || echo "❌ LLM not configured"
```

**If something is missing:** Run the appropriate setup (see Troubleshooting section).

### Step 3: Execute Scan

```bash
# Run in background with output capture
exaai -n --target https://shop.example.com --prompt-modules sql_injection \
  > /tmp/exaai_scan.log 2>&1 &

# Save the PID
echo $! > /tmp/exaai_scan.pid
```

### Step 4: Monitor Progress

```bash
# Check if still running
ps -p $(cat /tmp/exaai_scan.pid) > /dev/null && echo "Running..." || echo "Complete"

# View live output
tail -20 /tmp/exaai_scan.log

# Check results directory
ls -la exaai_runs/ | tail -5
```

### Step 5: Parse and Report Results

```bash
# Find latest run
LATEST_RUN=$(ls -td exaai_runs/*/ | head -1)

# Read summary
cat "$LATEST_RUN/report.md"

# Parse JSON for programmatic access
cat "$LATEST_RUN/report.json" | jq '.findings[] | {severity, title, url}'
```

**Notify user with summary:**
```
🛡️ Security Scan Complete: https://shop.example.com

📊 Results:
• Critical: 1
• High: 2  
• Medium: 3
• Low: 5

🚨 Critical Finding:
**SQL Injection** in `/api/products?id=`
- Payload: `' OR '1'='1 --`
- Impact: Full database access possible
- Fix: Use parameterized queries

Reply "full report" for detailed findings.
```

---

## 🔧 Error Handling & Self-Repair

### When Errors Occur

The agent should **automatically attempt to fix** common issues:

### Error: "Docker not running"
```bash
# Attempt to start Docker
sudo systemctl start docker || open -a Docker

# Wait and verify
sleep 5
docker info && echo "Docker started successfully"
```

### Error: "LLM API error" / "Invalid API key"
```
Ask user:
"🔑 There was an issue with your LLM API key. Please verify:
1. The key is correct and active
2. You have sufficient credits/quota
3. The model name matches your plan

Current config:
- Model: $EXAAI_LLM
- Base URL: ${LLM_API_BASE:-default}

Would you like to reconfigure?"
```

### Error: "Module not found"
```bash
# Search for similar module names
find /path/to/ExaAiAgent -name "*.jinja" -o -name "*.py" | xargs grep -l "module_name"

# Check available modules
ls exaaiagnt/prompts/vulnerabilities/
```

### Error: "exaai command not found"
```bash
# Reinstall
pipx install exaai-agent --force

# Or with pip
pip install --upgrade exaai-agent
```

### Error: Unknown/Unexpected
```bash
# 1. Check logs for details
cat /tmp/exaai_scan.log | tail -50

# 2. Search codebase for error handling
grep -r "error_message" /path/to/ExaAiAgent/

# 3. Check GitHub issues
# Search: https://github.com/hleliofficiel/ExaAiAgent/issues?q=error_message
```

---

## 🛠️ Contributing to ExaAiAgent

As an open-source project, the agent can **contribute improvements**:

### Finding Issues to Fix

```bash
# Check open issues
gh issue list --repo hleliofficiel/ExaAiAgent

# View specific issue
gh issue view 123 --repo hleliofficiel/ExaAiAgent
```

### Creating Bug Reports

```bash
gh issue create --repo hleliofficiel/ExaAiAgent \
  --title "Bug: [Short description]" \
  --body "## Description
What happened.

## Steps to Reproduce
1. Step one
2. Step two

## Expected Behavior
What should happen.

## Logs
\`\`\`
Paste relevant logs here
\`\`\`

## Environment
- ExaAiAgent version: $(exaai --version)
- OS: $(uname -a)
- Python: $(python --version)
"
```

### Submitting Improvements

```bash
# 1. Clone the repo
git clone https://github.com/hleliofficiel/ExaAiAgent.git
cd ExaAiAgent

# 2. Create feature branch
git checkout -b feature/improvement-name

# 3. Make changes (prompts are in .jinja format!)
# Edit: exaaiagnt/prompts/vulnerabilities/new_module.jinja
# Edit: exaaiagnt/tools/new_tool/new_tool_actions.py

# 4. Run tests
make test

# 5. Commit with conventional format
git add .
git commit -m "feat: add new security module for XYZ"

# 6. Push and create PR
git push origin feature/improvement-name
gh pr create --title "feat: Add XYZ security module" \
  --body "## Summary
What this PR does.

## Changes
- Added new_module.jinja prompt
- Added new_tool.py implementation

## Testing
Tested with: exaai -n --target https://example.com --prompt-modules new_module
"
```

### Prompt File Format

All prompts use **Jinja2 template format** (`.jinja`), NOT `.py`:

```jinja
{# exaaiagnt/prompts/vulnerabilities/example.jinja #}
{% block system %}
You are a security expert analyzing {{ target_type }} for {{ vulnerability_type }}.

## Objective
{{ objective }}

## Methodology
1. Reconnaissance
2. Vulnerability identification
3. Exploitation attempt
4. PoC generation

{% if instructions %}
## Additional Instructions
{{ instructions }}
{% endif %}
{% endblock %}
```

---

## 📦 Available Security Modules

| Module | Auto-Detect Trigger | Description |
|--------|---------------------|-------------|
| `sql_injection` | DB-related endpoints | SQL/NoSQL injection testing |
| `xss` | HTML responses | Cross-Site Scripting |
| `ssrf` | URL parameters | Server-Side Request Forgery |
| `rce` | Command params | Remote Code Execution |
| `idor` | ID/UUID params | Insecure Direct Object Reference |
| `authentication_jwt` | Auth endpoints | JWT vulnerabilities |
| `csrf` | Form submissions | Cross-Site Request Forgery |
| `race_condition` | State-changing ops | Race condition exploits |
| `graphql_security` | `/graphql` endpoint | GraphQL-specific attacks |
| `websocket_security` | `wss://` URLs | WebSocket vulnerabilities |
| `oauth_oidc` | `/oauth`, `/authorize` | OAuth2/OIDC flaws |
| `waf_bypass` | WAF detected | WAF bypass techniques |
| `subdomain_takeover` | Domain targets | Subdomain takeover |
| `prompt_injection` | AI/LLM endpoints | AI prompt injection (50+ payloads) |
| `kubernetes_security` | K8s targets | RBAC, PSS, NetworkPolicy audit |
| `cloud_security` | AWS/Azure/GCP | Cloud misconfiguration |

---

## 🔗 Resources

- **GitHub:** https://github.com/hleliofficiel/ExaAiAgent
- **Issues:** https://github.com/hleliofficiel/ExaAiAgent/issues
- **PyPI:** https://pypi.org/project/exaai-agent/
- **Contributing:** https://github.com/hleliofficiel/ExaAiAgent/blob/main/CONTRIBUTING.md

---

## 📝 Quick Reference

```bash
# Install
pipx install exaai-agent

# Configure (example: OpenRouter)
export EXAAI_LLM="openrouter/auto"
export LLM_API_KEY="your-key"
export LLM_API_BASE="https://openrouter.ai/api/v1"

# Scan (headless for agents)
exaai -n --target https://example.com

# Scan with TUI (interactive)
exaai --target https://example.com

# Specific modules
exaai -n --target https://api.example.com --prompt-modules graphql_security,authentication_jwt

# Check version
exaai --version
```
