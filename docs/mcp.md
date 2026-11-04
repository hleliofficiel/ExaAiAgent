# MCP tool layer (v3 direction)

Per PentestMCP (arXiv:2510.03610): one MCP server per tool family (nmap-mcp, nuclei-mcp, zap-mcp, graphql-mcp, cloud-mcp) in its own hardened container, argv-only (never shell=True), allowlisted args, egress allowlist to authorized scope. ExaAiAgent v3 keeps the existing registry/executor as the compatibility layer and exposes the same tools via MCP stdio/SSE without requiring a rewrite.

Security: MCP servers are an attack surface (CVE-2025-59834, CVE-2025-53100) — the scope guard (`exaaiagnt/safety/`) runs on both client and sandbox side.
