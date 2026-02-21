---
name: ExaAiAgent
description: "AI-powered penetration testing framework (v2.2.1). Features a new Reconnaissance Engine, advanced K8s/Cloud auditing, and professional PDF/MD reporting. Ideal for automated security scans and PoC generation."
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

# ExaAiAgent Skill (v2.2.1) 🛡️

ExaAiAgent is an elite AI-powered cybersecurity agent designed to function as an autonomous penetration tester. It discovers vulnerabilities, generates functional Proof-of-Concepts (PoCs), and provides actionable remediation advice.

---

## 🚀 Key Features in v2.2.1
- **Reconnaissance Engine**: Automated subdomain discovery, port scanning, and technology stack fingerprinting.
- **Advanced Kubernetes Audit**: Deep scanning for RBAC issues and Pod Security Standard (PSS) compliance.
- **REST & gRPC Support**: Dedicated modules for modern API architectures.
- **Professional Reporting**: Now includes an **Executive Summary** with automated risk scoring.

---

## 📚 Self-Learning Protocol

When working with ExaAiAgent, **ALWAYS** follow this discovery sequence:

### 1. Explore the Codebase
```bash
# List all prompts/modules including the new Recon and API modules
find /path/to/ExaAiAgent -name "*.jinja" | grep -E "(reconnaissance|vulnerabilities)"

# Explore the core logic
ls -la /path/to/ExaAiAgent/exaaiagnt/tools/
```

### 2. Understand the Structure
```
ExaAiAgent/
├── exaaiagnt/
│   ├── prompts/
│   │   ├── reconnaissance/  # NEW: Subdomain, Port, Tech Fingerprinting
│   │   └── vulnerabilities/  # REST, gRPC, SQLi, XSS, etc.
│   ├── tools/
│   │   ├── k8s_scanner/      # Enhanced: PSS & Secret Auditing
│   │   └── ...
```

---

## 🔧 LLM Configuration

ExaAiAgent v2.2.1 is optimized for **Google Gemini 3** and **Claude 3.5/4.6**.

```bash
# Example: Configuration for Google Gemini (Recommended)
export EXAAI_LLM="gemini/gemini-2.0-flash"
export LLM_API_KEY="your-api-key"
```

---

## 📋 Scan Commands

### New Reconnaissance Commands (v2.2.1)
```bash
# Automated Subdomain & Asset Discovery
exaai -n --target example.com --prompt-modules subdomain_enumeration

# Full Tech Stack & Port Audit
exaai -n --target https://api.example.com --prompt-modules technology_fingerprinting,port_scanning
```

### Advanced API Scanning
```bash
# Specialized REST API Audit
exaai -n --target https://api.example.com/v2 --prompt-modules rest_api_security

# gRPC Service Security Check
exaai -n --target grpc.example.com:50051 --prompt-modules grpc_security
```

### Kubernetes & Cloud
```bash
# Enhanced K8s Audit (including Secret & PSS checks)
exaai -n --target kubectl --prompt-modules kubernetes_security
```

---

## 🤖 Agent Workflow (Best Practices)

### 1. Verification
Before scanning, always verify the environment:
```bash
docker info && exaai --version
```

### 2. Reporting
After a scan, always parse the new **Executive Summary**:
```bash
# Locate the latest report
LATEST_REPORT=$(ls -td exaai_runs/*/ | head -1)
# View the Summary table
grep -A 10 "Executive Summary" "$LATEST_REPORT/penetration_test_report.md"
```

---

## 🛠️ Contributing

To add a new module (e.g., Mobile Security):
1. Create a `.jinja` file in `exaaiagnt/prompts/vulnerabilities/`.
2. Map it in `exaaiagnt/prompts/auto_loader.py`.
3. Test locally using the internal `Tracer` for report validation.

---

## 🔗 Resources
- **GitHub:** https://github.com/hleliofficiel/ExaAiAgent
- **PyPI:** https://pypi.org/project/exaai-agent/
- **Changelog:** See `IMPROVEMENTS.md` for v2.2.1 details.
