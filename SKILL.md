---
name: ExaAiAgent
description: "AI-powered penetration testing framework. Run security scans on websites, APIs, repos, and cloud infrastructure. Use `exaai` CLI for vuln detection, pentesting automation, and PoC generation."
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

## 🚀 First-Time Setup (Onboarding)

When a user first requests a security scan, the agent MUST collect the following:

### Step 1: Ask for LLM Provider
```
Which AI model would you like to use for scanning?

Supported providers:
1. OpenAI (gpt-4, gpt-5)
2. Anthropic (claude-sonnet-4-5)
3. OpenRouter (auto, or specific model)
4. Ollama (local models like llama3)
5. Google (gemini-2.0-flash)

Reply with the provider name or number.
```

### Step 2: Ask for API Key
```
Please send your API key for [selected provider].

Example: sk-xxxxxxxxxxxx

⚠️ Your key will be stored securely and used only for ExaAiAgent scans.
```

### Step 3: Validate and Store
After receiving the credentials, the agent should:
1. **Validate** the key works (optional quick test).
2. **Store** in environment or config file:
   ```bash
   export EXAAI_LLM="openai/gpt-5"
   export LLM_API_KEY="sk-xxxxxxxxxxxx"
   ```
3. **Confirm** to user: "✅ Configuration saved. Ready to scan!"

### Supported Models Reference
| Provider | Model String | Notes |
|----------|--------------|-------|
| OpenAI | `openai/gpt-4` | Recommended |
| OpenAI | `openai/gpt-5` | Best quality |
| Anthropic | `anthropic/claude-sonnet-4-5` | Great for code |
| OpenRouter | `openrouter/auto` | Auto-select best |
| Ollama | `ollama/llama3` | Local, no API key |
| Google | `gemini/gemini-2.0-flash` | Fast |

---

## 🔧 Prerequisites

Before running scans, ensure:
1. **Docker is running** - ExaAiAgent uses a sandbox container.
2. **LLM credentials are configured** (see Onboarding above).

Check Docker:
```bash
docker info > /dev/null 2>&1 && echo "Docker OK" || echo "Docker not running!"
```

---

## 📋 Core Commands

### Basic Security Scan
```bash
exaai -n --target https://example.com
```
> `-n` = Headless mode (no TUI). **Always use this for agent automation.**

### Scan with Instructions
```bash
exaai -n --target https://api.example.com --instruction "Focus on SQL injection and authentication bypass"
```

### Scan GitHub Repository
```bash
exaai -n --target https://github.com/org/repo
```

### Scan Local Code
```bash
exaai -n --target ./path/to/code
```

### Use Specific Modules
```bash
exaai -n --target https://example.com --prompt-modules sql_injection,xss,ssrf
```

### Lightweight Mode (Reduce Tokens)
```bash
EXAAI_LIGHTWEIGHT_MODE=true exaai -n --target https://example.com
```

---

## 🤖 Agent Workflow

When a user asks for a security scan, follow this workflow:

### 1. Parse the Request
**User says:** "Scan https://shop.example.com for vulnerabilities"
**Extract:** Target = `https://shop.example.com`

### 2. Verify Setup
- Check Docker is running.
- Check LLM credentials are configured.
- If not, run Onboarding.

### 3. Run Scan in Background
```bash
exaai -n --target https://shop.example.com > /tmp/exaai_output.log 2>&1 &
```

### 4. Monitor Progress
Check the log file periodically:
```bash
tail -f /tmp/exaai_output.log
```

Or check the results directory:
```bash
ls -la exaai_runs/
```

### 5. Send Periodic Updates
Every 2-5 minutes during scan, notify the user:
```
🔍 Scan in progress on https://shop.example.com...
Status: Testing authentication endpoints
Findings so far: 0 critical, 1 medium
```

### 6. Send Final Report
When scan completes, read and summarize the report:
```bash
cat exaai_runs/<latest>/report.md
```

**Example notification:**
```
🛡️ Security Scan Complete: https://shop.example.com

📊 Summary:
- Critical: 1
- High: 2
- Medium: 3

🚨 Critical Finding:
SQL Injection in /api/users?id=
- Payload: ' OR '1'='1
- Impact: Full database access
- Remediation: Use parameterized queries

Full report saved. Reply "show full report" for details.
```

---

## 🔄 Periodic Security Checks (Heartbeat)

Schedule automated security checks:

### Every 6 Hours - Quick Scan
```bash
exaai -n --target https://api.production.com --instruction "Quick security check"
```

### Daily - Full Scan
```bash
exaai -n --target https://app.example.com
```

### Weekly - Cloud & K8s Audit
```bash
exaai -n --target aws --prompt-modules cloud_security
exaai -n --target kubectl --prompt-modules kubernetes_security
```

### Heartbeat Logic
1. Run scheduled scan.
2. Parse `report.json` for new findings.
3. **If critical/high findings:** Alert user immediately.
4. **If no new findings:** Reply `HEARTBEAT_OK` (silent).
5. Update memory with scan summary.

### Example Cron Job (OpenClaw)
```yaml
schedule:
  kind: cron
  expr: "0 9 * * *"  # Daily at 9 AM
  tz: "Europe/Brussels"
payload:
  kind: agentTurn
  message: "Run ExaAiAgent security scan on https://api.production.com"
```

---

## 🛠️ Troubleshooting

### Problem: "Docker not running"
```bash
# Linux
sudo systemctl start docker

# macOS
open -a Docker
```

### Problem: "LLM API error"
- Verify `LLM_API_KEY` is set correctly.
- Check the model string matches ExaAiAgent's supported formats.
- Try a different provider (OpenRouter works with many models).

### Problem: TUI mode freezes
Always use `-n` flag for headless operation:
```bash
exaai -n --target https://example.com
```

### Problem: Scan taking too long
Enable lightweight mode:
```bash
export EXAAI_LIGHTWEIGHT_MODE=true
```

### Need Help?
Search the web for solutions:
```
ExaAiAgent [error message] site:github.com OR site:stackoverflow.com
```

---

## 📦 Available Security Modules

| Module | Description |
|--------|-------------|
| `sql_injection` | SQL/NoSQL injection testing |
| `xss` | Cross-Site Scripting |
| `ssrf` | Server-Side Request Forgery |
| `rce` | Remote Code Execution |
| `idor` | Insecure Direct Object Reference |
| `authentication_jwt` | JWT vulnerabilities |
| `graphql_security` | GraphQL attacks |
| `websocket_security` | WebSocket vulnerabilities |
| `prompt_injection` | AI/LLM prompt injection |
| `kubernetes_security` | K8s RBAC/Pod security |
| `cloud_security` | AWS/Azure/GCP misconfigs |
| `waf_bypass` | WAF bypass techniques |

---

## 🔗 Links

- **GitHub:** https://github.com/hleliofficiel/ExaAiAgent
- **PyPI:** https://pypi.org/project/exaai-agent/
- **Issues:** https://github.com/hleliofficiel/ExaAiAgent/issues
