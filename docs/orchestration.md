# Multi-agent orchestration (v3)

Hierarchical: Planner -> Recon / Vuln-Analysis / Exploit / Reporter, plus a Verifier/Reconciler node that re-checks findings (with evidence only, not the finder's conclusion) before reporting. LangGraph is the recommended orchestrator (explicit state = attack graph + findings, OTel per tool call); LiteLLM is the single model gateway (planner=strong reasoning, recon=cheap/fast, exploit=strong, reporter=cheap). Human-in-the-loop gate before exploitation (configurable per scope, MANTIS pattern).
