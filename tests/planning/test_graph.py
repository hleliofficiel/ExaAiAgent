from exaaiagnt.planning import AttackGraph, GraphNode, NodeType, NodeStatus, suggest_chains


def test_graph_flow():
    g = AttackGraph()
    g.add_node(GraphNode(node_id="a", node_type=NodeType.ENDPOINT, label="sqli error endpoint"))
    g.add_node(
        GraphNode(node_id="b", node_type=NodeType.FINDING, label="db read", prerequisites=["a"])
    )
    assert g.topological_next()[0].node_id == "a"
    try:
        g.set_status("a", NodeStatus.CONFIRMED)
        assert False, "should require evidence"
    except ValueError:
        pass
    g.set_status("a", NodeStatus.CONFIRMED, evidence_ids=["ev_1"])
    assert g.topological_next()[0].node_id == "b"


def test_chains():
    g = AttackGraph()
    g.add_node(GraphNode(node_id="a", node_type=NodeType.FINDING, label="sqli error confirmed"))
    g.set_status("a", NodeStatus.CONFIRMED, evidence_ids=["ev_x"])
    chains = suggest_chains(g)
    assert any("sqli" in c.label for c in chains)


def _n(i, label="x", pre=(), risk=1, status=NodeStatus.DISCOVERED):
    return GraphNode(
        node_id=i, node_type=NodeType.FINDING, label=label, prerequisites=list(pre),
        risk=risk, status=status,
    )


def test_cycle_detection_and_self_requirement():
    import pytest

    g = AttackGraph()
    with pytest.raises(ValueError):
        g.add_node(_n("s", pre=["s"]))
    g.add_node(_n("a", pre=["b"]))
    g.add_node(_n("b", pre=["a"]))
    assert g.has_cycle()
    assert g.topological_next() == []


def test_dead_prerequisite_makes_dependents_unreachable():
    g = AttackGraph()
    g.add_node(_n("a", status=NodeStatus.FALSE_POSITIVE))
    g.add_node(_n("b", pre=["a"]))
    g.add_node(_n("c", pre=["b"]))
    g.add_node(_n("d"))
    assert g.unreachable_nodes() == {"b", "c"}
    assert [n.node_id for n in g.topological_next()] == ["d"]


def test_claim_next_assigns_and_release_frees():
    g = AttackGraph()
    g.add_node(_n("a", risk=3))
    g.add_node(_n("b", risk=2))
    first = g.claim_next("ag1", 1)
    second = g.claim_next("ag2", 1)
    assert [n.node_id for n in first] == ["a"]
    assert [n.node_id for n in second] == ["b"]
    assert g.claim_next("ag3", 1) == []
    assert g.release("ag1") == 1
    assert [n.node_id for n in g.claim_next("ag3", 1)] == ["a"]


def test_chain_prerequisites_are_only_the_matching_findings():
    from exaaiagnt.planning import add_suggested_chains

    g = AttackGraph()
    g.add_node(_n("n1", label="sqli in /login", status=NodeStatus.CONFIRMED))
    g.add_node(_n("n2", label="open port 22", status=NodeStatus.CONFIRMED))
    chains = suggest_chains(g)
    sq = [c for c in chains if c.node_id == "chain_sqli_db"][0]
    assert sq.prerequisites == ["n1"]
    assert [c.node_id for c in add_suggested_chains(g)] == ["chain_sqli_db"]
    assert add_suggested_chains(g) == []  # idempotent, no duplicate-node error
    assert "chain_sqli_db" in g.to_dict()["nodes"][2]["node_id"]
