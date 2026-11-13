# Migration v3.0.1 -> v3.1.1

## New in this release (additive)

- `exaai mcp` — MCP stdio server working identically as `exaai mcp`, `ExaAiAgent mcp`, `exaaiagent mcp`
- Dashboard v2: WebSocket live events + `/api/state`, `/api/report`, `/api/export/{json,sarif,csv,html,md}`; no breaking changes

Unchanged: all v3.1.1 security defaults (litellm 1.101.x, dashboard bound to 127.0.0.1 with optional `EXAAI_DASHBOARD_TOKEN`).

v3.1.1 is a security maintenance release. The CLI, commands, and config keys are unchanged; a few defaults and dependencies changed.

| Area | Change | Action needed |
|---|---|---|
| `litellm` | upgraded to >=1.101.3 (<1.102.0); proxy extras included | Recreate your virtual environment or `pip install -U litellm>=1.101.3`; old litellm releases are affected by multiple CVEs |
| `openai` | requirement is now >=2.20.0,<4.0.0 | Automatic on fresh install; remove any local pin to 1.x |
| `gql` / `graphql-core` | gql 3 -> 4 (graphql-core >=3.2.12); the old gql 3 cap on graphql-core made CVE fixes unresolvable | No code changes for standard `Client`/`gql`/`RequestsHTTPTransport` usage |
| Python requirement | >=3.12,<3.14 | Use Python 3.12 or 3.13 |
| Dashboard | binds `127.0.0.1:8000` by default (was 0.0.0.0) | If you accessed the dashboard from another host, pass `host="0.0.0.0"` explicitly, or set `EXAAI_DASHBOARD_TOKEN` and use a reverse proxy with Bearer auth |
| Tool server `/health` | unauthenticated responses now return only `{"status":"healthy"}`; full detail requires the Bearer token | Internal callers passing the token are unaffected |
| `tool_server` token | passed via `EXAAI_TOOL_SERVER_TOKEN` environment variable instead of `--token` argv | If you launched `tool_server.py` directly, set the env var instead of `--token` (argv still accepted for compatibility) |
| `python_action` / terminal | unchanged behavior; outbound prompt-injection probe now passes through the URL blocklist | No action |
| `_scope_check` | fails closed if the safety guard cannot load (was silently allowing) | Scans with `EXAAI_TARGETS` set now abort with `GUARD_ERROR` instead of running unscoped when the guard is broken — this is the safe direction |
| Dependencies | multiple bumps (see CHANGELOG): starlette 1.10, fastapi 0.162, cryptography 50, urllib3 2.8, requests 2.33+, etc. | Fresh install recommended |

Upgrade:

```bash
# pipx
pipx install --force git+https://github.com/hleliofficiel/ExaAiAgent.git

# or pip
pip install --user --upgrade git+https://github.com/hleliofficiel/ExaAiAgent.git
```

Then `exaai --version` should print `ExaAi v3.1.1`.

## Dashboard v2.1 (this update, same release)

New ops panel in the dashboard UI — no changes required:

- **AI Providers**: view configured LLM providers (masked keys only), live reachability Test per provider, set active provider/model, `PUT /api/providers/env` for key edits (allowlisted keys, atomic `.env` rewrite + `.env.bak-<UTCts>` backup, `chmod 600`, live `os.environ` for the running process; restart for fresh processes)
- **Update badge**: shows when a newer `exaai-agent` release exists on PyPI (checked every 6h, offline-safe)
- **Scan Control**: STOP button aborts the scan at the next tool-boundary boundary; a tool already running finishes first; stop is same-process only
- **Audit log**: `GET /api/audit` — JSONL at `exaai_runs/_dashboard_audit.jsonl`, recording `env_set`, `scan_stop_requested`, `provider_tested` (never key values)
- **Export All (.zip)**: `GET /api/export/full` with `report.json|sarif|csv|html|md` + `manifest.json`
- **Print / PDF**: toolbar button + print CSS for a clean report page
