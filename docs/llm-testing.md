# LLM / MCP / RAG Testing

Offline, deterministic security checkers for LLM-integrated components.
No network, no LLM calls: `exaaiagnt/llm_tests/mcp_rag.py` exposes pure
functions over strings/dicts so they can gate findings, CI, and MCP server
registration. Each checker is mapped to the OWASP Top 10 for LLM
Applications (2025), `LLM01`–`LLM10`.

## Checkers

| Checker | OWASP | What it catches |
|---|---|---|
| `detect_prompt_injection(text)` | LLM01 | ignore/disregard/former instructions, role impersonation, reveal-system-prompt requests, jailbreak phrases, exfiltration/tool-abuse requests, chat-template delimiter spoofing, zero-width characters |
| `detect_system_prompt_leak(text, known_fragments)` | LLM07 / LLM02 | leak phrases ("my system prompt is…"), canary fragments of the real system prompt, API keys, bearer tokens, private keys, AWS keys, password assignments |
| `audit_mcp_manifest(manifest)` / `manifest_passes(manifest)` | LLM01/02/03/06/10 | broad permissions (`filesystem:*`), dangerous tools (`exec`, `rm`, …), instruction-override text, unpinned versions, missing auth, missing tool timeouts |
| `check_rag_document(doc)` | LLM04 / LLM08 | missing source, untrusted source, missing `source_uri`, missing `tenant_id`, content-hash mismatch, embedded injection payloads |
| `check_cross_tenant_leak(request_tenant, docs)` | LLM08 / LLM02 | retrieved docs belonging to another tenant |
| `semantic_manipulation_heuristics(text)` | LLM04 / LLM09 | repetition/keyword stuffing, authority+urgency framing, zero-width chars, link density, embedded instructions |
| `evaluate_rag_corpus(request_tenant, docs)` | all of the above | aggregate verdict for a retrieved corpus |

## Verification hardening

`exaaiagnt/verification/hardening.py` (additive — `pipeline.py` is
unchanged) wires the checkers into finding verification:

- `harden_finding_text(text, known_fragments)` — injection + leak +
  manipulation checks over a finding's text.
- `harden_rag_evidence(request_tenant, docs)` — provenance + cross-tenant
  checks over the RAG documents backing a finding.
- `should_downgrade(hardening)` — returns `(True, reason)` when a
  high-severity injection, a secret leak, or a cross-tenant leak should
  prevent a `confirmed` status; low-signal heuristics alone do not.

## Tests

`tests/llm_tests/test_mcp_rag.py` — run with
`pytest tests/llm_tests tests/verification`.
