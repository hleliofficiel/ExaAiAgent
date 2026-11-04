from __future__ import annotations

from exaaiagnt.planning.graph import AttackGraph, GraphNode, NodeStatus, NodeType


def suggest_chains(graph: AttackGraph) -> list[GraphNode]:
    out = []
    confirmed = {n.node_id for n in graph.nodes.values() if n.status == NodeStatus.CONFIRMED}
    labels = {n.node_id: n.label.lower() for n in graph.nodes.values()}

    def has(*words):
        return any(w in labels[c] for c in confirmed for w in words)

    if has("version", "fingerprint") and has("cve"):
        out.append(
            GraphNode(
                node_id="chain_version_cve",
                node_type=NodeType.FINDING,
                label="version disclosure + CVE match",
                prerequisites=sorted(confirmed),
                expected_evidence="cve_match with fingerprinted version",
            )
        )
    if has("sqli", "sql error"):
        out.append(
            GraphNode(
                node_id="chain_sqli_db",
                node_type=NodeType.IMPACT,
                label="sqli error -> db read",
                prerequisites=sorted(confirmed),
                expected_evidence="boolean/time differential + data sample",
            )
        )
    if has("ssrf", "metadata"):
        out.append(
            GraphNode(
                node_id="chain_ssrf_meta",
                node_type=NodeType.IMPACT,
                label="ssrf -> cloud metadata",
                prerequisites=sorted(confirmed),
                expected_evidence="internal fetch proof, scope allow_internal_ssrf",
            )
        )
    if has("idor", "bola"):
        out.append(
            GraphNode(
                node_id="chain_idor_tenant",
                node_type=NodeType.IMPACT,
                label="idor -> cross-tenant read",
                prerequisites=sorted(confirmed),
                expected_evidence="two-account ID swap evidence",
            )
        )
    return out
