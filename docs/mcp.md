# MCP server (`exaai mcp`)

ExaAiAgent exposes itself to any Model Context Protocol client (Claude Desktop, Cursor, Continue, OpenClaw, ...) over **stdio** via the official `mcp` SDK.

```bash
exaai mcp            # serve MCP over stdio
exaai mcp --help     # print help, exit without serving
```

Client configuration (Claude Desktop example):

```json
{
  "mcpServers": {
    "exaai": { "command": "exaai", "args": ["mcp"] }
  }
}
```

## Exposed tools

| Tool | What it does | Safety |
|---|---|---|
| `exaai_run_scan` | Full scan (`exaai --target <t> -n` equivalent). Returns a concise summary (run name, finding counts, report path, top confirmed findings with `evidence_id`s). Never returns raw `report.json` | Requires non-empty `EXAAI_TARGETS` containing the target, else it refuses before any tool runs |
| `exaai_cve_lookup` | Look up a CVE in the pinned KB | Routed through the standard executor (`_scope_check`, manifest, evidence recording) |
| `exaai_list_runs` | List `exaai_runs/<name>` newest first | Path-sanitized |
| `exaai_get_report` | Summary of `exaai_runs/<run>/report.json` | `run_name` must match `^[A-Za-z0-9_.-]+$`; contained under `exaai_runs/` |

Report contents are consumed inside the same `executor` used by the CLI, so every scope/blocklist/budget guarantee applies identically.

## Design notes

- stdio transport only (no network listener by default)
- Server name `exaai-agent`; logs go to **stderr** (stdout carries the JSON-RPC channel)
- All errors return `isError=True` with no traceback leakage
- No raw `report.json` is ever returned in-band (size + information hygiene)

This is the minimal, shipping version of the MCP integration. The per-tool-family hardened MCP servers (nmap-mcp, nuclei-mcp, ...) described in the v3 direction notes remain future work.
