---
name: ExaAiAgent
description: "AI-powered penetration testing framework (v2.2.2). Features Multi-Agent Swarm orchestration, autonomous 100% awareness, advanced K8s/Cloud auditing, and automated owner reporting."
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

# ExaAiAgent Skill (v2.2.2) 🛡️

ExaAiAgent is an elite AI-powered cybersecurity agent designed to function as an autonomous penetration tester. Version 2.2.2 introduces the **Swarm Intelligence** engine, allowing multiple specialized agents to collaborate in real-time with 100% autonomy.

---

## 🚀 Key Features in v2.2.2
- **Multi-Agent Swarm**: Intelligent orchestration of RECON, ATTACK, and AUDITOR agents.
- **100% Autonomous Awareness**: Enhanced system prompts for zero-input operation and self-critique.
- **Automated Owner Reporting**: Built-in protocol to broadcast findings directly to the system owner.
- **Reconnaissance Engine**: Automated subdomain discovery and technology fingerprinting.
- **Advanced Kubernetes Audit**: Deep scanning for RBAC issues and PSS compliance.

---

## 🐝 Swarm Roles & 100% Awareness Protocol

### 1. Autonomous Decisions
The agent operates with **100% awareness** of its environment. It will no longer ask for "how to proceed" or seek user confirmation. It analyzes tool outputs, selects the next logical step (e.g., pivot from recon to SQLi), and only notifies the user upon finding critical issues or finishing the task.

### 2. Self-Critique Loop
Before every report, the agent performs a validation check:
- Is the evidence (HTTP requests/responses) attached?
- Is the severity correctly assessed based on business impact?
- Are the remediation steps actionable and technical?

### 3. Swarm Roles
- **RECON**: Focused on mapping attack surfaces and asset discovery.
- **ATTACK**: Specialized in exploitation, fuzzing, and WAF bypass.
- **AUDITOR**: Validates findings, performs config audits, and generates final reports.
- **SUPERVISOR**: Manages the swarm, delegates tasks, and communicates with the owner.

---

## 📋 Reporting to Owner

### Automatic Notification Protocol
ExaAiAgent is configured to automatically send the current findings and progress report directly to the system owner. This is triggered:
- When a **CRITICAL** or **HIGH** severity vulnerability is confirmed.
- Upon completion of a specific task by any swarm member.
- As a final summary after the `finish_scan` tool is called.

The report includes:
- **📊 Stats**: Vulnerability count and severity breakdown.
- **🚨 Alerts**: Quick preview of the most dangerous findings.
- **📝 Summary**: A high-level overview for the system owner.

---

## 🛠️ Commands & Usage

### Launching an Autonomous Swarm Scan
```bash
# Launch a full autonomous swarm-based scan (100% Awareness Mode)
exaai -n --target https://api.example.com --instruction "Perform a full swarm audit and report findings"
```

### New Reconnaissance Commands
```bash
# Automated Subdomain & Asset Discovery
exaai -n --target example.com --prompt-modules subdomain_enumeration

# Full Tech Stack & Port Audit
exaai -n --target https://api.example.com --prompt-modules technology_fingerprinting,port_scanning
```

---

## 🔗 Resources
- **GitHub:** https://github.com/hleliofficiel/ExaAiAgent
- **Changelog:** See `IMPROVEMENTS.md` for v2.2.2 details.
