from __future__ import annotations

from exaaiagnt.planning.graph import AttackGraph, GraphNode, NodeStatus, NodeType


def suggest_chains(graph: AttackGraph) -> list[GraphNode]:
    out = []
    confirmed = {n.node_id for n in graph.nodes.values() if n.status == NodeStatus.CONFIRMED}
    labels = {n.node_id: n.label.lower() for n in graph.nodes.values()}

    def matching(*words) -> list[str]:
        return sorted(c for c in confirmed if any(w in labels[c] for w in words))

    def has(*words):
        return bool(matching(*words))

    if has("version", "fingerprint") and has("cve"):
        out.append(
            GraphNode(
                node_id="chain_version_cve",
                node_type=NodeType.FINDING,
                label="version disclosure + CVE match",
                prerequisites=sorted(set(matching("version", "fingerprint")) | set(matching("cve"))),
                expected_evidence="cve_match with fingerprinted version",
            )
        )
    if has("sqli", "sql error"):
        out.append(
            GraphNode(
                node_id="chain_sqli_db",
                node_type=NodeType.IMPACT,
                label="sqli error -> db read",
                prerequisites=matching("sqli", "sql error"),
                expected_evidence="boolean/time differential + data sample",
            )
        )
    if has("ssrf", "metadata"):
        out.append(
            GraphNode(
                node_id="chain_ssrf_meta",
                node_type=NodeType.IMPACT,
                label="ssrf -> cloud metadata",
                prerequisites=matching("ssrf", "metadata"),
                expected_evidence="internal fetch proof, scope allow_internal_ssrf",
            )
        )
    if has("idor", "bola"):
        out.append(
            GraphNode(
                node_id="chain_idor_tenant",
                node_type=NodeType.IMPACT,
                label="idor -> cross-tenant read",
                prerequisites=matching("idor", "bola"),
                expected_evidence="two-account ID swap evidence",
            )
        )
    # Skip chains that are already in the graph so callers can re-run this safely.
    return [c for c in out if c.node_id not in graph.nodes]


def add_suggested_chains(graph: AttackGraph) -> list[GraphNode]:
    """Add new chain suggestions (idempotent). Returns the nodes that were added."""
    added = []
    for node in suggest_chains(graph):
        graph.add_node(node)
        added.append(node)
    return added
