---
name: exaai
description: "AI-powered penetration testing framework. Run security scans on websites, APIs, repos, and cloud infrastructure. Use `exaai` CLI for vuln detection, pentesting automation, and PoC generation."
homepage: https://github.com/hleliofficiel/ExaAiAgent
metadata:
  {
    "openclaw":
      {
        "emoji": "🛡️",
        "requires": { "bins": ["exaai"], "env": ["EXAAI_LLM", "LLM_API_KEY"] },
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

## Prerequisites

1. **Docker** must be running (ExaAiAgent uses a sandbox).
2. **LLM Provider** configured via environment variables.

## Configuration

Set these environment variables before using:

```bash
# Required: Choose your LLM provider
export EXAAI_LLM="openai/gpt-5"          # or anthropic/claude-sonnet-4-5
export LLM_API_KEY="your-api-key"

# Optional: Performance tuning
export EXAAI_LIGHTWEIGHT_MODE=true       # Reduce token usage
export EXAAI_MAX_TOKENS=2048             # Limit output tokens
```

## Quick Commands

### Basic Security Scan
```bash
exaai --target https://example.com
```

### Scan with Specific Instructions
```bash
exaai --target https://api.example.com --instruction "Test for SQL injection and SSRF"
```

### Headless Mode (Non-Interactive)
Best for agent automation - no TUI, just output:
```bash
exaai -n --target https://example.com
```

### Scan a GitHub Repository
```bash
exaai --target https://github.com/org/repo
```

### Scan Local Codebase
```bash
exaai --target ./path/to/code
```

### GraphQL API Security
```bash
exaai --target https://api.example.com/graphql --prompt-modules graphql_security
```

### Kubernetes Cluster Audit
```bash
exaai --target kubectl --instruction "Audit RBAC and Pod Security"
```

## Smart Auto-Loading

ExaAiAgent automatically loads relevant security modules based on target type:

| Target Pattern | Auto-Loaded Module |
|----------------|-------------------|
| `*/graphql` | `graphql_security` |
| `wss://` | `websocket_security` |
| `*/oauth/*` | `oauth_oidc` |
| Domain only | `subdomain_takeover` |

## Output

Results are saved to `exaai_runs/<run-name>/` including:
- `report.json` - Machine-readable findings
- `report.md` - Human-readable report
- Screenshots and PoCs

## Agent Usage Examples

### Example 1: Quick Website Audit
**User says:** "Scan https://shop.example.com for vulnerabilities"
**Agent runs:**
```bash
exaai -n --target https://shop.example.com
```

### Example 2: Authenticated Testing
**User says:** "Test the admin panel with credentials admin:pass123"
**Agent runs:**
```bash
exaai -n --target https://example.com/admin --instruction "Authenticated testing with credentials admin:pass123"
```

### Example 3: CI/CD Integration Check
**User says:** "Check if this repo has security issues"
**Agent runs:**
```bash
exaai -n --target https://github.com/user/repo
```

### Example 4: Cloud Security Review
**User says:** "Audit my AWS configuration"
**Agent runs:**
```bash
exaai -n --target aws --prompt-modules cloud_security --instruction "Check for S3 misconfigs and IAM issues"
```

## Available Security Modules

| Module | Description |
|--------|-------------|
| `sql_injection` | SQL/NoSQL injection |
| `xss` | Cross-Site Scripting |
| `ssrf` | Server-Side Request Forgery |
| `rce` | Remote Code Execution |
| `idor` | Insecure Direct Object Reference |
| `authentication_jwt` | JWT vulnerabilities |
| `graphql_security` | GraphQL attacks |
| `prompt_injection` | AI/LLM prompt injection |
| `kubernetes_security` | K8s RBAC/Pod security |
| `waf_bypass` | WAF bypass techniques |

## Tips for Agents

1. **Always use `-n` (headless mode)** for non-interactive execution.
2. **Check Docker is running** before starting a scan.
3. **Parse `report.json`** for structured results.
4. **Set `EXAAI_LIGHTWEIGHT_MODE=true`** to reduce LLM costs.
5. **Use `--instruction`** to guide the scan focus.

## Troubleshooting

**"Docker not running"** - Start Docker Desktop or daemon.
**"LLM API error"** - Check `LLM_API_KEY` is set correctly.
**"Module not found"** - Use `--prompt-modules` to specify manually.

## Links

- **GitHub:** https://github.com/hleliofficiel/ExaAiAgent
- **PyPI:** https://pypi.org/project/exaai-agent/
- **Documentation:** See README.md in repo
