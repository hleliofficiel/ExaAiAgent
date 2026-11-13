# Migration v3.1.1 -> v3.2.0

No breaking changes. Two additive features ship in this release.

## `exaai mcp` — MCP stdio server

Works with all entry points (`exaai`, `ExaAiAgent`, `exaaiagent`):

```bash
exaai mcp           # starts the MCP stdio server
exaai mcp --help    # shows help and exits
```

Claude Desktop / Cursor / Continue configuration:

```json
{
  "mcpServers": {
    "exaai": { "command": "exaai", "args": ["mcp"] }
  }
}
```

Exposed tools: `exaai_run_scan`, `exaai_cve_lookup`, `exaai_list_runs`, `exaai_get_report`.

Requirements: the `mcp` package (already pulled in by the `litellm[proxy]` extra) and `EXAAI_TARGETS` set to the assets you are authorized to test — `exaai_run_scan` refuses to run without a matching scope entry.

## Dashboard v2

```bash
exaai tui            # or run the agent; dashboard spawns automatically on 127.0.0.1:8000
```

- Live event feed and counters over WebSocket (existing endpoints unchanged)
- New: `/api/state`, `/api/report`, `/api/export/{json,sarif,csv,html,md}`
- `EXAAI_DASHBOARD_TOKEN` still gates `/api/*` and `/ws` exactly as before

Upgrade:

```bash
pipx install --force git+https://github.com/hleliofficiel/ExaAiAgent.git
exaai --version   # ExaAi v3.2.0
```
