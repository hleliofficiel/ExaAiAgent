from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class NodeType(StrEnum):
    ASSET = "asset"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    AUTH_SURFACE = "auth_surface"
    FINGERPRINT = "fingerprint"
    FINDING = "finding"
    PRIMITIVE = "primitive"
    IMPACT = "impact"


class NodeStatus(StrEnum):
    DISCOVERED = "discovered"
    SUSPECTED = "suspected"
    VALIDATED = "validated"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    BLOCKED = "blocked"


class GraphNode(BaseModel):
    node_id: str
    node_type: NodeType
    label: str
    status: NodeStatus = NodeStatus.DISCOVERED
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    prerequisites: list[str] = Field(default_factory=list)
    expected_evidence: str = ""
    risk: int = 1
    est_cost_requests: int = 1
    assigned_agent_id: str | None = None


class EdgeType(StrEnum):
    EXPOSES = "exposes"
    CONTROLS = "controls"
    REACHES = "reaches"
    ENABLES = "enables"
    REQUIRES = "requires"
    CHAINABLE_TO = "chainable_to"


class GraphEdge(BaseModel):
    from_node: str
    to_node: str
    edge_type: EdgeType
    note: str = ""


class AttackGraph:
    def __init__(self):
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []

    def add_node(self, node: GraphNode):
        if node.node_id in self.nodes:
            raise ValueError(f"duplicate node {node.node_id}")
        self.nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge):
        if edge.from_node not in self.nodes or edge.to_node not in self.nodes:
            raise ValueError("edge endpoints must exist")
        self.edges.append(edge)

    def set_status(
        self,
        node_id: str,
        status: NodeStatus,
        evidence_ids: list[str] | None = None,
        confidence: float | None = None,
    ):
        n = self.nodes[node_id]
        if status in (NodeStatus.VALIDATED, NodeStatus.CONFIRMED):
            ev = evidence_ids if evidence_ids is not None else n.evidence_ids
            if not ev:
                raise ValueError("validated/confirmed requires evidence_ids")
            n.evidence_ids = list(ev)
        if confidence is not None:
            n.confidence = confidence
        n.status = status

    def topological_next(self, k: int = 5) -> list[GraphNode]:
        done = {nid for nid, n in self.nodes.items() if n.status == NodeStatus.CONFIRMED}
        ready = []
        for n in self.nodes.values():
            if n.status in (NodeStatus.CONFIRMED, NodeStatus.FALSE_POSITIVE, NodeStatus.BLOCKED):
                continue
            if all(p in done for p in n.prerequisites):
                ready.append(n)
        ready.sort(key=lambda n: (-n.risk, n.est_cost_requests, -n.confidence))
        return ready[:k]
