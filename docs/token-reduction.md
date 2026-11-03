# Token / cost reduction (OWASP LLM10)
- Budgets enforced: EXAAI_MAX_SCAN_TOKENS (default 2M), EXAAI_MAX_TOOL_CALLS (500), EXAAI_MAX_AGENTS (8), token hard-stop in agent_loop + circuit breaker (5 consecutive errors)
- Context: EXAAI_MAX_CONTEXT_TOKENS (90k) for compressor; EXAAI_SUMMARIZER_MODEL for cheap summarization routing
- Tool outputs: EXAAI_TOOL_OUTPUT_MAX_CHARS (8000) truncation in output processor; full output spilled to EvidenceStore (hash + excerpt)
- Spawn: inherit_context defaults to False (no full parent history copy); max 5 prompt modules/child
- Per-tool timeout: EXAAI_TOOL_TIMEOUT (120s) via asyncio.wait_for; sandbox retry 3x with exponential backoff on 5xx
