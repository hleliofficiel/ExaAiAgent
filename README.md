<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0.4-00f5ff?style=for-the-badge&logo=rocket" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.12+-00ff88?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-bf00ff?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/AI-Powered-ff8800?style=for-the-badge&logo=openai" alt="AI Powered">
</p>

<h1 align="center">
  <br>
  🔒 ExaAi Agent 🔒
  <br>
</h1>

<h3 align="center">
  <em>Advanced AI-Powered Cybersecurity Agent for Comprehensive Penetration Testing</em>
</h3>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-modules">Modules</a>
</p>

---

## ⚡ What's New in v2.0.4

| Feature | Description |
|---------|-------------|
| 🎯 **Agent Supervisor** | Heartbeat monitoring, timeout detection, self-healing |
| 🧠 **Shared Memory** | Inter-agent communication, deduplication |
| 🛡️ **WAF Bypass** | Cloudflare, Akamai, Imperva detection & bypass |
| 📊 **Scan Modes** | Stealth / Standard / Aggressive |
| 🔧 **Tool Manager** | Process isolation, auto-restart |
| 💾 **Output Processor** | 80%+ token reduction |

---

## 🚀 Features

### 🤖 AI-Powered Security Testing

- **Autonomous scanning** with intelligent decision-making
- **Multi-agent architecture** for parallel testing
- **Context-aware exploitation** with memory persistence

### 🛡️ Comprehensive Security Coverage

```
✓ SQL Injection          ✓ XSS (Reflected/Stored/DOM)
✓ SSRF                   ✓ IDOR
✓ Authentication Bypass  ✓ API Security
✓ SSTI                   ✓ HTTP Smuggling
✓ Deserialization        ✓ Prototype Pollution
✓ Cache Poisoning        ✓ Path Traversal
```

### 🎛️ Operational Modes

| Mode | Requests/min | Use Case |
|------|-------------|----------|
| 🥷 **Stealth** | 10 | Production-safe, minimal footprint |
| ⚖️ **Standard** | 60 | Bug bounty, safe fuzzing |
| 🔥 **Aggressive** | 300 | Full exploitation, PoC development |

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/exaai/exaai-agent.git
cd exaai-agent

# Install dependencies
pip install poetry
poetry install

# Set up environment
cp .env.example .env
# Edit .env with your API keys
```

---

## 🎮 Usage

### CLI Mode

```bash
# Basic scan
exaai scan https://target.com

# With specific mode
exaai scan https://target.com --mode stealth

# With custom config
exaai scan https://target.com --config custom.yaml
```

### TUI Mode (Interactive)

```bash
exaai tui
```

### Python API

```python
from exaaiagnt.agents import ExaaiAgent, ScanMode, get_scan_mode_manager

# Configure scan mode
mode_manager = get_scan_mode_manager()
mode_manager.set_mode(ScanMode.STANDARD)

# Start agent
agent = ExaaiAgent(config={
    "target": "https://target.com",
    "llm_config": your_config
})

# Run scan
results = await agent.run()
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ExaAi Agent v2.0.4                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Recon      │  │   Scanner    │  │   Exploit    │   │
│  │   Agent      │──│   Agent      │──│   Agent      │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
│          │                │                │             │
│          └────────────────┼────────────────┘             │
│                           │                              │
│                  ┌────────▼────────┐                     │
│                  │ Agent Supervisor │                    │
│                  │  • Heartbeat     │                    │
│                  │  • Timeout       │                    │
│                  │  • Recovery      │                    │
│                  └────────┬────────┘                     │
│                           │                              │
│          ┌────────────────┼────────────────┐             │
│          │                │                │             │
│  ┌───────▼───────┐ ┌──────▼──────┐ ┌───────▼───────┐    │
│  │ Shared Memory │ │ Scan Modes  │ │ WAF Bypass    │    │
│  │  • URLs       │ │ • Stealth   │ │ • Detection   │    │
│  │  • Endpoints  │ │ • Standard  │ │ • Encoding    │    │
│  │  • Vulns      │ │ • Aggressive│ │ • Smuggling   │    │
│  └───────────────┘ └─────────────┘ └───────────────┘    │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## 📚 Modules

### 🎯 Agent Supervisor

```python
from exaaiagnt.agents import get_supervisor, AgentPriority

supervisor = get_supervisor()
supervisor.register_agent(id, name, priority=AgentPriority.HIGH, token_budget=200000)
supervisor.heartbeat(id)
supervisor.pause_agent(id)
supervisor.resume_agent(id)
```

### 🧠 Shared Memory

```python
from exaaiagnt.agents import get_shared_memory, store_url, DataCategory

memory = get_shared_memory()
store_url("https://api.target.com/v1/users", "recon_agent")
urls = memory.get_unscanned_urls("scanner_agent")
```

### 🛡️ WAF Bypass

```python
from exaaiagnt.tools import detect_waf, generate_bypasses

result = detect_waf(status_code=403, headers=resp.headers, body=resp.text)
if result.detected:
    print(f"WAF: {result.waf_type.value}")
    bypasses = generate_bypasses("<script>alert(1)</script>")
```

### 📊 Scan Modes

```python
from exaaiagnt.agents import get_scan_mode_manager, ScanMode

manager = get_scan_mode_manager()
manager.set_mode(ScanMode.AGGRESSIVE)

if manager.can_fuzz():
    # Fuzzing allowed
    pass
```

---

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `EXAAI_SCAN_MODE` | stealth / standard / aggressive | standard |
| `EXAAI_FALLBACK_MODELS` | Comma-separated fallback models | - |
| `LLM_RATE_LIMIT_DELAY` | Delay between requests (seconds) | 2.0 |
| `LLM_REQUEST_TIMEOUT` | Request timeout (seconds) | 300 |

---

## 📈 Performance

| Metric | Before | After v2.0.4 |
|--------|--------|--------------|
| Token Usage | 100% | **20%** (-80%) |
| Agent Freezes | Common | **Rare** |
| Recovery Time | Manual | **Auto (< 5min)** |
| WAF Blocks | Crash | **Bypass Attempted** |

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built with ❤️ by the ExaAi Team</strong>
  <br>
  <sub>Advanced AI Security for Everyone</sub>
</p>
