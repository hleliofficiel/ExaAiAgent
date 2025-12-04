# 📚 ExaaiAgnt Prompt Modules

## 🎯 Overview

Prompt modules are specialized knowledge packages that enhance ExaaiAgnt agents with deep expertise in specific vulnerability types, technologies, and testing methodologies. Each module provides advanced techniques, practical examples, and validation methods that go beyond baseline security knowledge.

---

## 🏗️ Architecture

### How Prompts Work

When an agent is created, it can load up to 5 specialized prompt modules relevant to the specific subtask and context at hand:

```python
# Agent creation with specialized modules
create_agent(
    task="Test authentication mechanisms in API",
    name="Auth Specialist",
    prompt_modules="authentication_jwt,business_logic,api_security"
)
```

The modules are dynamically injected into the agent's system prompt, allowing it to operate with deep expertise tailored to the specific vulnerability types or technologies required for the task at hand.

---

## 📁 Available Modules

### Vulnerability Testing Modules

| Module | Description |
|--------|-------------|
| `sql_injection` | SQL/NoSQL injection techniques and bypass methods |
| `xss` | Cross-Site Scripting discovery and exploitation |
| `ssrf` | Server-Side Request Forgery attacks |
| `xxe` | XML External Entity injection |
| `rce` | Remote Code Execution techniques |
| `csrf` | Cross-Site Request Forgery testing |
| `idor` | Insecure Direct Object Reference |
| `authentication_jwt` | JWT and authentication bypass |
| `business_logic` | Business logic vulnerability hunting |
| `race_conditions` | Race condition and TOCTOU exploits |
| `path_traversal` | Directory traversal attacks |

### NEW: Advanced Modules

| Module | Description |
|--------|-------------|
| `api_security` | REST, GraphQL, gRPC API security testing |
| `cloud_security` | AWS, Azure, GCP security assessment |
| `reconnaissance_osint` | Reconnaissance and OSINT techniques |
| `privilege_escalation` | Linux/Windows privilege escalation |
| `high_impact_bugs` | Bug bounty hunting for critical vulns |
| `post_exploitation` | Post-exploitation and lateral movement |

---

## 📁 Module Categories

| Category | Purpose |
|----------|---------|
| **`/vulnerabilities`** | Core vulnerability testing (SQLi, XSS, SSRF, RCE, etc.) |
| **`/frameworks`** | Framework-specific testing (Django, Express, FastAPI, Next.js) |
| **`/technologies`** | Third-party services (Supabase, Firebase, Auth0) |
| **`/protocols`** | Protocol testing (GraphQL, WebSocket, OAuth) |
| **`/cloud`** | Cloud security (AWS, Azure, GCP, Kubernetes) |
| **`/reconnaissance`** | Information gathering and enumeration |
| **`/custom`** | Community-contributed modules |

---

## 🎨 Creating New Modules

### What Should a Module Contain?

A good prompt module is a structured knowledge package that typically includes:

- **Advanced techniques** - Non-obvious methods specific to the task and domain
- **Practical examples** - Working payloads, commands, or test cases with variations
- **Automation scripts** - Python/Bash scripts for automated testing
- **Validation methods** - How to confirm findings and avoid false positives
- **Context-specific insights** - Environment nuances and edge cases

### Module Template

```jinja
<module_name>
MODULE TITLE

Brief description of the module's focus area.

## Core Techniques
- Technique 1 with examples
- Technique 2 with examples

## Automation Scripts
```python
# Example automation code
```

## Checklist

- [ ] Test item 1
- [ ] Test item 2
</module_name>

```

---

## 🤝 Contributing

Community contributions are welcome! Submit new modules via pull requests to help expand the collection.

---

> [!NOTE]
> **ExaaiAgnt v1.0** - Comprehensive prompt module collection with advanced techniques for professional security testing.
