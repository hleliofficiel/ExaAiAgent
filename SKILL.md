---
name: exaaiagent
description: Use ExaAiAgent for AI-assisted penetration testing, security scans, attack-surface mapping, repo/code security review, and multi-agent offensive-security workflows. Trigger when a user wants to run, debug, review, extend, or operate ExaAiAgent itself; when an agent should launch ExaAiAgent scans; or when another AI agent needs onboarding instructions for using ExaAiAgent safely and correctly.
---

# ExaAiAgent Skill

Use ExaAiAgent as a Docker-backed security testing framework driven by LiteLLM-compatible models.

## Operate the tool

- Ensure Docker is installed and running.
- Ensure Python 3.12+ is available.
- Ensure a LiteLLM-compatible model is configured through environment variables.
- First run pulls the sandbox image automatically.

Minimum environment:

```bash
export EXAAI_LLM="openrouter/auto"
export LLM_API_KEY="..."
# optional when provider requires a custom base
export LLM_API_BASE="https://openrouter.ai/api/v1"
```

Basic commands:

```bash
# non-interactive CLI scan
exaai -n --target https://example.com

# interactive TUI
exaai tui

# repository or local code
exaai --target https://github.com/org/repo
exaai --target ./app
```

## Understand the runtime

- ExaAiAgent depends on Docker for its sandbox runtime.
- If Docker is unavailable, startup fails before the scan loop begins.
- Tool execution happens through the sandbox tool server.
- Prompt modules are auto-resolved when the user does not specify them explicitly.

## Diagnose common failures

### Docker not available

Check:

```bash
docker version
docker info
```

If Docker is not reachable, fix Docker before debugging higher layers.

### LLM/provider issues

Check:

- `EXAAI_LLM`
- `LLM_API_KEY`
- `LLM_API_BASE` when needed
- model/provider compatibility with LiteLLM

### Tool/runtime issues

If the scan starts but tools fail:

- inspect sandbox startup
- inspect tool server health
- inspect missing host dependencies required by the chosen tool path

## Develop ExaAiAgent itself

When modifying ExaAiAgent:

1. Fix runtime/CLI/TUI issues before adding new features.
2. Keep version strings synchronized in:
   - `pyproject.toml`
   - `exaaiagnt/interface/main.py`
   - `exaaiagnt/interface/tui.py`
   - `README.md`
3. Run targeted tests first, then broader test batches.
4. Prefer improving error surfacing over silent failure.
5. Keep LiteLLM as the provider abstraction layer; avoid login-session provider hacks unless explicitly requested.

Useful checks:

```bash
pytest -q
python -m py_compile exaaiagnt/interface/main.py exaaiagnt/interface/tui.py exaaiagnt/runtime/tool_server.py
exaai --version
```

## Release checklist

Before a release:

- confirm tests pass
- confirm version strings are aligned
- confirm README changelog/announcement is updated
- confirm Docker requirement is documented clearly
- confirm at least one real startup path was exercised

## Safety note

Only run ExaAiAgent on assets the operator is authorized to test.
