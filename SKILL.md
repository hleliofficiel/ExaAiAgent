---
name: exaaiagent
description: "Run, debug, maintain, or extend ExaAiAgent for AI-assisted penetration testing, attack-surface mapping, repo/code security review, and multi-agent offensive-security workflows. Use when an AI agent needs onboarding instructions for operating ExaAiAgent, when a user wants to launch scans from CLI/TUI, when ExaAiAgent itself needs maintenance, or when another agent should use ExaAiAgent with any LiteLLM-supported provider (OpenAI, Anthropic, OpenRouter, Ollama, Gemini-compatible endpoints, and other LiteLLM-backed providers)."
---

# ExaAiAgent Skill

Use ExaAiAgent as a Docker-backed security testing framework powered by **LiteLLM-compatible providers**.

## Core operating rules

- Treat `EXAAI_LLM` as the active model selector; set `LLM_API_KEY` and `LLM_API_BASE` only when the chosen provider needs them.
- The first run pulls the sandbox Docker image automatically.
- Save results under `exaai_runs/<run-name>`.
- Use only on assets the operator is authorized to test.

## Installation and first scan

Install ExaAiAgent with either method:

```bash
# Method 1: pip
pip install exaai-agent

# Method 2: pipx
pipx install exaai-agent
```

Configure a LiteLLM-supported provider using the pattern `export EXAAI_LLM="provider/model-name"`. Set `LLM_API_KEY` and `LLM_API_BASE` when the provider requires them.

| Provider | `EXAAI_LLM` | `LLM_API_KEY` | `LLM_API_BASE` |
|----------|-------------|---------------|-----------------|
| OpenAI | `openai/gpt-5` | required | — |
| Anthropic | `anthropic/claude-sonnet-4-5` | required | — |
| OpenRouter | `openrouter/auto` | required | `https://openrouter.ai/api/v1` |
| Ollama | `ollama/llama3` | — | `http://localhost:11434` |
| Other | `provider/model-name` | if needed | if needed |

Verify the setup before scanning:

```bash
docker version && exaai --version
```

Run the first scan and verify results:

```bash
exaai --target https://your-app.com
# Check results — if empty or errored, re-run with verbose output
ls exaai_runs/*/  || exaai --target https://your-app.com --verbose
```

## Basic usage

```bash
# Local codebase
exaai --target ./app-directory

# GitHub repository review
exaai --target https://github.com/org/repo

# Black-box web assessment
exaai --target https://your-app.com

# Headless mode
exaai -n --target https://your-app.com

# Interactive mode
exaai tui
```

## Smart auto-loading

ExaAiAgent auto-resolves prompt modules when `--prompt-modules` is not set.

```bash
exaai --target https://api.example.com/graphql          # GraphQL
exaai --target wss://chat.example.com/socket             # WebSocket
exaai --target https://auth.example.com/oauth/authorize  # OAuth/OIDC
exaai --target example.com --instruction "enumerate subdomains"  # Recon
```

## Advanced usage

```bash
# Authenticated or grey-box testing
exaai --target https://your-app.com --instruction "Perform authenticated testing using provided credentials and identify authorization flaws"

# Multi-target testing
exaai -t https://github.com/org/app -t https://your-app.com

# Explicit modules
exaai --target https://api.example.com --prompt-modules graphql_security,waf_bypass

# Lightweight mode
EXAAI_LIGHTWEIGHT_MODE=true exaai --target https://example.com --instruction "quick security scan"
```

## Diagnose common failures

Follow this order — each layer depends on the one above it:

1. **Docker**: Run `docker version && docker info`. Fix Docker before debugging anything else.
2. **Provider/LiteLLM**: Verify `EXAAI_LLM`, `LLM_API_KEY`, and `LLM_API_BASE` (when applicable). Confirm the provider/model pair is supported by LiteLLM.
3. **Tool/runtime**: If startup succeeds but scan execution fails, inspect sandbox startup, tool-server health, missing system dependencies, and model/provider rate limits.

## Maintain ExaAiAgent itself

When editing ExaAiAgent:

1. Fix runtime, CLI, TUI, and tool-server issues before adding new features.
2. Keep version strings synchronized in `pyproject.toml`, `exaaiagnt/interface/main.py`, `exaaiagnt/interface/tui.py`, and `README.md`.
3. Keep LiteLLM as the model-provider abstraction layer.
4. Prefer stronger error surfacing over silent failure.

Before release, confirm tests pass, CI is green, version strings are aligned, docs are updated, and at least one real startup path was exercised.

```bash
pytest -q
python -m py_compile exaaiagnt/interface/main.py exaaiagnt/interface/tui.py exaaiagnt/runtime/tool_server.py
exaai --version
```
