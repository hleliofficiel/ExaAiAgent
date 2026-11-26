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
        if node.node_id in node.prerequisites:
            raise ValueError(f"node {node.node_id} cannot require itself")
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

    _DEAD = (NodeStatus.FALSE_POSITIVE, NodeStatus.BLOCKED)

    def has_cycle(self) -> bool:
        """True if prerequisites contain a cycle (such nodes can never become ready)."""
        state: dict[str, int] = {}

        def visit(nid: str) -> bool:
            state[nid] = 1
            for p in self.nodes[nid].prerequisites:
                if p not in self.nodes:
                    continue
                if state.get(p) == 1:
                    return True
                if p not in state and visit(p):
                    return True
            state[nid] = 2
            return False

        return any(nid not in state and visit(nid) for nid in self.nodes)

    def unreachable_nodes(self) -> set[str]:
        """Nodes that can never run: a prerequisite is false-positive/blocked/missing."""
        dead = {nid for nid, n in self.nodes.items() if n.status in self._DEAD}
        changed = True
        while changed:
            changed = False
            for nid, n in self.nodes.items():
                if nid in dead or n.status == NodeStatus.CONFIRMED:
                    continue
                if any(p in dead or p not in self.nodes for p in n.prerequisites):
                    dead.add(nid)
                    changed = True
        return {nid for nid in dead if self.nodes[nid].status not in self._DEAD}

    def topological_next(self, k: int = 5, include_assigned: bool = True) -> list[GraphNode]:
        done = {nid for nid, n in self.nodes.items() if n.status == NodeStatus.CONFIRMED}
        blocked_chain = self.unreachable_nodes()
        ready = []
        for n in self.nodes.values():
            if n.status in (NodeStatus.CONFIRMED, NodeStatus.FALSE_POSITIVE, NodeStatus.BLOCKED):
                continue
            if n.node_id in blocked_chain:
                continue
            if not include_assigned and n.assigned_agent_id:
                continue
            if all(p in done for p in n.prerequisites):
                ready.append(n)
        # Highest risk first, then cheapest, then most confident; node_id keeps it deterministic.
        ready.sort(key=lambda n: (-n.risk, n.est_cost_requests, -n.confidence, n.node_id))
        return ready[: max(k, 0)]

    def claim_next(self, agent_id: str, k: int = 1) -> list[GraphNode]:
        """Assign up to k ready, unassigned nodes to an agent so agents do not duplicate work."""
        picked = self.topological_next(k, include_assigned=False)
        for n in picked:
            n.assigned_agent_id = agent_id
        return picked

    def release(self, agent_id: str) -> int:
        """Free every unfinished node held by an agent (e.g. it failed or timed out)."""
        freed = 0
        for n in self.nodes.values():
            if n.assigned_agent_id == agent_id and n.status not in (
                NodeStatus.CONFIRMED,
                NodeStatus.FALSE_POSITIVE,
            ):
                n.assigned_agent_id = None
                freed += 1
        return freed

    def to_dict(self) -> dict:
        return {
            "nodes": [n.model_dump(mode="json") for n in self.nodes.values()],
            "edges": [e.model_dump(mode="json") for e in self.edges],
        }
