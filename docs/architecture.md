# ExaAiAgent v3 Architecture

```
exaai --target ... -> DockerSandbox (hardened, 127.0.0.1 ports, no host ~/.kube)
  -> ToolServer (Bearer, compare_digest, 630s timeout, async-aware)
  -> Executor -> EvidenceStore (every tool result gets ev_<hash>)
  -> Grounding gate (validate_claim) -> Reporting (SARIF/JSON/CSV)
  -> Planning graph (AttackGraph) + CVE KB (pinned snapshot) + Confidence (conf-v1)
```

- 31 registered tools + 58 prompt modules (prompt-only modules marked as such)
- OWASP Top 10:2025 mapping: SSRF->A01, supply-chain->A03, exceptional conditions->A10
- MCP tool-server pattern, LangGraph orchestrator, per-agent LiteLLM routing: see docs/mcp.md, docs/orchestration.md
