---
name: ExaAiAgent
description: "Use and contribute to ExaAiAgent — run AI-assisted penetration tests, map attack surfaces, review code security, and maintain the tool itself. For any agent helping a user operate ExaAiAgent or contributing to its development: installation, configuration, running and interpreting scans, contributing code, prompt modules, tools, tests, and releases. Works with any LiteLLM-supported provider (OpenAI, Anthropic, OpenRouter, Ollama, Gemini-compatible endpoints, and other LiteLLM-backed providers)."
---

# ExaAiAgent Skill

Use ExaAiAgent as a Docker-backed security testing framework powered by **LiteLLM-compatible providers**. Current version: **v3.2.0**.

This skill has two audiences:

- **Part A — Using ExaAiAgent** for running scans and interpreting results (users and the agents assisting them)
- **Part B — Contributing to ExaAiAgent** for developing, reviewing, and releasing the tool

Use only against assets you are authorized to test.

## Core operating rules

- Treat `EXAAI_LLM` as the active model selector; set `LLM_API_KEY` and `LLM_API_BASE` only when the chosen provider needs them.
- The first run pulls the sandbox Docker image automatically.
- Save results under `exaai_runs/<run-name>`.
- Set `EXAAI_TARGETS` to enforce target scope before tool execution.
- Every finding must be grounded in an `evidence_id`; reject invented CVE/version claims against the pinned CVE KB.
- Use only on assets the operator is authorized to test.

---

# Part A — Using ExaAiAgent

## Installation

Prerequisites: Docker (running), Python 3.12+.

```bash
pip install exaai-agent
# or, isolated install (recommended)
pipx install exaai-agent
```

Install from source:

```bash
git clone https://github.com/hleliofficiel/ExaAiAgent.git
cd ExaAiAgent
pipx install .
# or: pip install -e .
```

Configure a provider:

```bash
export EXAAI_LLM="provider/model-name"
export LLM_API_KEY="your-api-key"      # for hosted providers
export LLM_API_BASE="https://openrouter.ai/api/v1"   # for OpenRouter / local endpoints
```

| Provider | `EXAAI_LLM` | `LLM_API_KEY` | `LLM_API_BASE` |
|----------|-------------|---------------|-----------------|
| OpenAI | `openai/<model>` | required | - |
| Anthropic | `anthropic/<model>` | required | - |
| OpenRouter | `openrouter/auto` | required | `https://openrouter.ai/api/v1` |
| Ollama | `ollama/llama3` | - | `http://localhost:11434` |
| Other | `provider/model-name` | if needed | if needed |

Verify installation and Docker:

```bash
docker version && docker info
exaai --version
exaai --help
```

## First scan

```bash
exaai --target https://your-app.com
```

The first run pulls the sandbox image automatically; results land in `exaai_runs/<run-name>/`.

```bash
exaai --target ./app-directory                      # local codebase
exaai --target https://github.com/org/repo          # GitHub repository review
exaai --target https://your-app.com                 # web black-box
exaai -n --target https://your-app.com              # headless / CI mode
exaai tui                                           # interactive TUI
```

Smart auto-loading detects GraphQL, WebSocket, OAuth/OIDC, and recon surfaces from the target; pass `--prompt-modules` to override:

```bash
exaai --target https://api.example.com/graphql --prompt-modules graphql_security
exaai --target https://example.com --instruction "enumerate subdomains and report live hosts"
```

## Requesting a scan & replying to the user (for agents)

When a user asks something like "scan X for security issues", follow this flow:

1. **Confirm scope and authorization.** Identify the target, ask whether the user is authorized to test it, and set `EXAAI_TARGETS` to exactly those assets. Never scan targets the user has not authorized.
2. **Pick the mode and modules.** Let auto-loading decide unless the user asked for specific checks (`--prompt-modules`). Multi-target: repeat `-t`.
3. **Budget the run.** Defaults are safe; for big codebases set `EXAAI_MAX_SCAN_TOKENS` (e.g. `2000000`), `EXAAI_TOOL_TIMEOUT=120`. For lightweight triage: `EXAAI_LIGHTWEIGHT_MODE=true`.
4. **Run headless** for automation (`-n`), or the TUI (`exaai tui`) for an interactive session.
5. **Read the results.** Inspect `exaai_runs/<run-name>/`:
   - `report.md` / `report.json` — findings with `evidence_id`s, severity, confidence (`conf-v1`)
   - `run_metadata.json`, `agents.json`, `tool_executions.json`, `chat_messages.json` — what the agents actually did
   - `report.sarif` / `report.csv` / `report.html` — export formats
6. **Report back to the user** clearly and honestly:
   - State scope actually scanned, mode, and modules used
   - Lead with **confirmed** findings (with `evidence_id`, severity, affected location, and a safe one-line remediation), then **suspected** findings flagged as unverified
   - Quote the evidence briefly; never fabricate CVE IDs — every claim must cite its `evidence_id` or KB entry
   - If verification could not run, say so plainly instead of presenting unverified output as confirmed
   - Include reproduction notes only for authorized, controlled verification — never weaponized payloads against third parties
7. **Iterate**: answer follow-ups by re-running narrower scans (`--prompt-modules`, `--instruction`) rather than re-explaining prior output.

Quick scan-request template a user can send:

```text
Scan https://my-app.example.com for OWASP Top 10 issues.
Scope: only this host and its API at /api/*. Authorized for testing.
Prefer confirmed findings with evidence; flag anything unverified.
Focus: authz/IDOR and injection first, then SSRF. Lightweight mode if possible.
```

## Basic usage reference

```bash
exaai mcp                                # start MCP stdio server (any MCP client)
exaai --target <path|url>                 # single target
exaai -t <t1> -t <t2>                     # multi-target
exaai -n --target <url>                   # headless
exaai tui                                 # interactive
exaai --target <url> --instruction "..."  # guide the agents
exaai --target <url> --prompt-modules a,b # explicit modules
exaai --version
exaai --help
```

Budget and safety knobs: `EXAAI_MAX_SCAN_TOKENS`, `EXAAI_MAX_TOOL_CALLS`, `EXAAI_MAX_AGENTS`, `EXAAI_TOOL_TIMEOUT=120`, `EXAAI_TARGETS` (enforced scope).

## Capabilities (v3.2.0)

- **Evidence grounding:** every tool result gets an `evidence_id`; reports require evidence; invented CVE/version claims are rejected against the pinned CVE KB.
- **CVE intelligence:** EPSS, CISA KEV, OSV, GitHub Advisories, with provenance and version-range matching.
- **Independent verification:** hypothesis -> evidence -> independent check -> `conf-v1` -> confirmed / suspected / false_positive.
- **Scoped execution:** `TargetScope` + command guard + blocklist + proxy linkage enforce `EXAAI_TARGETS`; token/tool/spawn budgets and a circuit breaker stop runaway agents.
- **Sandbox hardening:** tool server on 127.0.0.1, no host `~/.kube` mount, `no-new-privileges`, no NET_RAW.
- **Reporting:** unified `report.json` plus SARIF/CSV/HTML/Markdown.
- **Prompt modules (64):** OWASP LLM Top 10 2025, supply-chain/SBOM triage, exceptional-conditions fail-open, grounded CVE verification, and more.
- **78 registered tools:** nuclei/ZAP/httpx-katana/OAST wrappers, HAR import/export, browser JS analysis, API auth/OpenAPI checks, secrets scanning, SBOM triage, cloud checks.
- **Coordination:** `RunState` save/load/resume, bounded queue, budget guard, stuck detection.
- **LLM/MCP/RAG checks:** offline OWASP LLM Top 10 (2025), MCP manifest audit, prompt-injection and leak detection, RAG provenance/cross-tenant checks.
- **Kubernetes scanner:** native K8s assessment.

## Diagnose common failures

Check in this order; each layer depends on the one above it.

1. **Docker:** `docker version && docker info`. Fix Docker first.
2. **Provider / LiteLLM:** verify `EXAAI_LLM`, `LLM_API_KEY`, `LLM_API_BASE`; modern models need a recent `litellm` (`pip install -U litellm`).
3. **PATH:** after install, `source ~/.bashrc` (or `~/.zshrc` / `fish_add_path ~/.local/bin`), or reopen the terminal. `pipx ensurepath` once if you used pipx.
4. **Tool / runtime:** sandbox startup, tool-server health, missing dependencies, rate limits. Check `exaai_runs/<run-name>/` — `chat_messages.json`, `run_metadata.json`, `agents.json`, `tool_executions.json`, `report.json`.

See the README "Troubleshooting" section for `exaai: command not found`, Docker permission errors, `LLM_API_KEY` 401/403, dashboard exposure, and upgrade conflicts.

---

# Part B — Contributing to ExaAiAgent

Welcome. This section is for developers and coding agents who want to help build ExaAiAgent.

## Development setup

```bash
git clone https://github.com/hleliofficiel/ExaAiAgent.git
cd ExaAiAgent
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"        # or: poetry install --with=dev
poetry run pytest -q           # 202 tests must pass
poetry run exaai --version     # expect: ExaAi v3.2.0
```

## How the project is organized

- `exaaiagnt/agents/` — supervisor, scan modes, shared memory
- `exaaiagnt/grounding/` — EvidenceStore (evidence_id gate)
- `exaaiagnt/knowledge/` — pinned CVE KB (`cves.jsonl`, schema)
- `exaaiagnt/intelligence/` — EPSS/KEV/OSV/GHSA feeds
- `exaaiagnt/verification/` — verification pipeline + hardening
- `exaaiagnt/safety/` — TargetScope, command guard, blocklist
- `exaaiagnt/tools/` — tool registry + wrappers
- `exaaiagnt/prompts/` — prompt modules (one `.jinja` per module)
- `exaaiagnt/interface/` — CLI / TUI
- `benchmark/` — deterministic Juice Shop / DVWA / WebGoat smoke tasks

## Contribution workflow

1. **Branch from `main`**: `git checkout -b <type>/<short-description>` (e.g. `feat/k8s-rbac-audit`, `fix/proxy-timeout`).
2. **Small, reviewable changes.** Prefer additive changes; avoid rewriting working components.
3. **Tests for every behavior change** — add/adjust tests under `tests/`; do not weaken existing assertions to make CI green.
4. **Run the gate locally** before pushing:

```bash
poetry run pytest -q -o addopts=''
poetry run ruff format --check <changed paths>
poetry run ruff check <changed paths>
poetry run bandit -r exaaiagnt -c pyproject.toml
poetry run mypy exaaiagnt/runtime/tool_server.py
```

5. **Open a PR against `main`.** CI must be green (lint, type-check, test, security, smoke). Keep the PR focused; link the issue it closes.
6. **Versioning**: version strings live in `exaaiagnt/version.py` and `pyproject.toml` — update both together for release prep. Do not tag or release without maintainer review.

## Adding a tool

- Implement as a function decorated with `@register_tool` in the relevant `exaaiagnt/tools/` module (module-level functions only, never classes).
- Argv-only invocation (no `shell=True`); timeout-bound; returns dicts with explicit error keys.
- Add the tool's schema next to the implementation (`*_schema.xml`) and wire it into the registry.
- Document it in `docs/tools.md` with a safe-usage example.
- Add tests covering success, failure, and blocked-input paths.

## Adding a prompt module

- One `.jinja` per module under `exaaiagnt/prompts/<category>/`; keep modules focused and self-contained.
- Ground claims: require `evidence_id` citations; no fabricated CVE/version claims — the gate rejects them.
- Reference OWASP/CWE identifiers where applicable.
- Register the module (auto-loader catalog) and add a smoke test if feasible.

## Code style and conventions

- Python 3.12+; type hints on public functions; argparse (not click) for CLI.
- Logging via `logging`, not `print` (except in `cli.py`/`tui.py` UI paths).
- No bare `except:` and no silent `except Exception: pass` without a `# nosec`-style justification comment.
- No new hard dependencies without discussion in the PR.
- Keep public APIs stable; if a change is breaking, open an issue first and discuss.

## CI on your PRs

Every PR runs: **lint** (ruff + bandit), **type-check** (mypy on critical paths), **test** (pytest), **security** (pip-audit on the locked set + bandit), **smoke** (CLI `--version` and parser). All must pass before merge.

## Reporting bugs and requesting features

- Bugs: use the issue tracker's bug template — include version (`exaai --version`), Docker version, provider/model, target type, a minimal reproduction, and `exaai_runs/<run-name>/` artifacts if shareable.
- Features: open a feature request with the user problem first, then a sketch of the solution. Proposed-but-unmerged ideas live in `ROADMAP.md`.
- Security vulnerabilities **in ExaAiAgent itself**: do not open a public issue — see `SECURITY.md` for responsible disclosure.

## Keeping your fork current

`main` is protected and updated frequently: work from a fresh clone or `git fetch origin && git rebase origin/main` before opening a PR. Dependabot PRs land weekly — review `poetry.lock` conflicts carefully (regenerate with `poetry lock`, do not hand-edit hashes).

## Best practices

Maintain backward compatibility, keep prompt modules focused, avoid unnecessary dependencies, write tests for every new feature, prefer readable code over clever code, and keep interfaces stable.

## Multi-agent guidelines

Keep agents specialized, avoid overlapping responsibilities, prefer composition over duplication, share artifacts through the workspace, and minimize unnecessary spawning.

## Instructions for AI coding agents

Understand the implementation before changing it; do not rewrite working components unnecessarily; preserve existing APIs; update tests when behavior changes; keep version strings synchronized; verify CI passes before finalizing; avoid breaking changes.
