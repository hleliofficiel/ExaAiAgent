---
name: ExaAiAgent
description: "Run, debug, maintain, or extend ExaAiAgent for AI-assisted penetration testing, attack-surface mapping, repo/code security review, and multi-agent offensive-security workflows. Use when an AI agent needs onboarding instructions for operating ExaAiAgent, when a user wants to launch scans from CLI/TUI, when ExaAiAgent itself needs maintenance, or when another agent should use ExaAiAgent with any LiteLLM-supported provider (OpenAI, Anthropic, OpenRouter, Ollama, Gemini-compatible endpoints, and other LiteLLM-backed providers)."
---

# ExaAiAgent Skill

Use ExaAiAgent as a Docker-backed security testing framework powered by **LiteLLM-compatible providers**. Current version: **v3.0.1**.

## Core operating rules

- Treat `EXAAI_LLM` as the active model selector; set `LLM_API_KEY` and `LLM_API_BASE` only when the chosen provider needs them.
- The first run pulls the sandbox Docker image automatically.
- Save results under `exaai_runs/<run-name>`.
- Set `EXAAI_TARGETS` to enforce target scope before tool execution.
- Every finding must be grounded in an `evidence_id`; reject invented CVE/version claims against the pinned CVE KB.
- Use only on assets the operator is authorized to test.

## Installation and first scan

```bash
pip install exaai-agent
# or
pipx install exaai-agent
```

Configure a LiteLLM-supported provider using `export EXAAI_LLM="provider/model-name"`.

| Provider | `EXAAI_LLM` | `LLM_API_KEY` | `LLM_API_BASE` |
|----------|-------------|---------------|-----------------|
| OpenAI | `openai/gpt-5.5` | required | - |
| Anthropic | `anthropic/claude-sonnet-5` | required | - |
| OpenRouter | `openrouter/auto` | required | `https://openrouter.ai/api/v1` |
| Ollama | `ollama/llama3` | - | `http://localhost:11434` |
| Other | `provider/model-name` | if needed | if needed |

Verify, then run the first scan:

```bash
docker version && exaai --version
exaai --target https://your-app.com
ls exaai_runs/*/  || exaai --target https://your-app.com --verbose
```

## Basic usage

```bash
exaai --target ./app-directory
exaai --target https://github.com/org/repo
exaai --target https://your-app.com
exaai -n --target https://your-app.com    # headless
exaai tui                                  # interactive
```

## Smart auto-loading

ExaAiAgent auto-resolves prompt modules when `--prompt-modules` is not set (GraphQL, WebSocket, OAuth/OIDC, recon, and others).

```bash
exaai --target https://api.example.com/graphql
exaai --target wss://chat.example.com/socket
exaai --target https://auth.example.com/oauth/authorize
exaai --target example.com --instruction "enumerate subdomains"
```

## Advanced usage

```bash
# Authenticated / grey-box testing
exaai --target https://your-app.com --instruction "Perform authenticated testing using provided credentials and identify authorization flaws"

# Multi-target, explicit modules, lightweight mode
exaai -t https://github.com/org/app -t https://your-app.com
exaai --target https://api.example.com --prompt-modules graphql_security,waf_bypass
EXAAI_LIGHTWEIGHT_MODE=true exaai --target https://example.com --instruction "quick security scan"
```

Budget and safety knobs: `EXAAI_MAX_SCAN_TOKENS`, `EXAAI_MAX_TOOL_CALLS`, `EXAAI_MAX_AGENTS`, `EXAAI_TOOL_TIMEOUT=120`, and `EXAAI_TARGETS` for enforced scope.

## Diagnose common failures

Check in this order; each layer depends on the one above it.

1. **Docker:** `docker version && docker info`. Fix Docker first.
2. **Provider / LiteLLM:** verify `EXAAI_LLM`, `LLM_API_KEY`, `LLM_API_BASE`; modern models need a recent `litellm` (`pip install -U litellm`).
3. **Tool / runtime:** sandbox startup, tool-server health, missing dependencies, rate limits. Check `exaai_runs/<run-name>/` for `chat_messages.json`, `run_metadata.json`, `agents.json`, `tool_executions.json`, and `report.json`.

## Capabilities (v3.0.1 - latest)

- **Evidence grounding:** every tool result gets an `evidence_id`; reports require evidence, invented CVE/version claims are rejected against the pinned CVE KB.
- **CVE intelligence:** EPSS, CISA KEV, OSV, and GitHub Advisories with provenance and version-range matching.
- **Independent verification:** hypothesis -> evidence -> independent check -> conf-v1 -> confirmed / suspected / false_positive, with hardening downgrades.
- **Scoped execution:** `TargetScope` + command guard + blocklist + proxy linkage enforce `EXAAI_TARGETS`; token/tool/spawn budgets and a circuit breaker stop runaway agents.
- **Sandbox hardening:** tool server on 127.0.0.1, no host `~/.kube` mount, `no-new-privileges`, no NET_RAW.
- **Reporting:** unified `report.json` plus SARIF/CSV/HTML/Markdown via `build_report` / `to_sarif`.
- **Prompt modules (64):** including OWASP LLM Top 10 2025, supply-chain/SBOM triage, exceptional-conditions fail-open, and grounded CVE verification.
- **78 registered tools:** nuclei/ZAP/httpx-katana/OAST wrappers, HAR import/export, browser JS analysis, API auth/OpenAPI checks, secrets scanner, SBOM triage, cloud checks.
- **Coordination:** `RunState` save/load/resume, bounded task queue, budget guard, stuck detection via `coordination_*` tools.
- **LLM/MCP/RAG tests:** offline OWASP LLM Top 10 (2025) checkers, MCP manifest audit (`audit_mcp_manifest_tool`), prompt-injection and leak detection, RAG provenance/cross-tenant checks.
- **Benchmark:** deterministic Juice Shop / DVWA / WebGoat smoke tasks in `benchmark/`.
- **Kubernetes scanner:** native K8s assessment; `@register_tool` only on tool functions, never on classes.

## Architecture overview

Multi-agent orchestration, LiteLLM abstraction, Docker sandbox, browser automation, proxy capture, tool server/registry, scanners, CLI/TUI. Main package: `exaaiagnt/`.

## Multi-agent guidelines

Keep agents specialized, avoid overlapping responsibilities, prefer composition over duplication, share artifacts through the workspace, minimize unnecessary spawning.

## Best practices

Maintain backward compatibility, keep prompt modules focused, avoid unnecessary dependencies, write tests for every new feature, prefer readable code, keep interfaces stable.

## Instructions for AI coding agents

Understand the implementation before changing it, do not rewrite working components unnecessarily, preserve existing APIs, update tests when behavior changes, keep version strings synchronized, verify CI passes before finalizing, avoid breaking changes.

## Maintenance checks

```bash
poetry run pytest -q
poetry run python -m py_compile exaaiagnt/interface/main.py exaaiagnt/interface/tui.py exaaiagnt/runtime/tool_server.py
poetry run exaai --version
```

Version is single-sourced in `exaaiagnt/version.py` (fallback `3.0.1`); `pyproject.toml` is the source of truth for packaging. Do not publish to PyPI until all features are verified and documented.
