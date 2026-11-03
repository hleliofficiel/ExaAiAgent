from exaaiagnt.planning import AttackGraph, GraphNode, NodeType, NodeStatus, suggest_chains
def test_graph_flow():
    g = AttackGraph()
    g.add_node(GraphNode(node_id="a", node_type=NodeType.ENDPOINT, label="sqli error endpoint"))
    g.add_node(GraphNode(node_id="b", node_type=NodeType.FINDING, label="db read", prerequisites=["a"]))
    assert g.topological_next()[0].node_id == "a"
    try:
        g.set_status("a", NodeStatus.CONFIRMED)
        assert False, "should require evidence"
    except ValueError: pass
    g.set_status("a", NodeStatus.CONFIRMED, evidence_ids=["ev_1"])
    assert g.topological_next()[0].node_id == "b"
def test_chains():
    g = AttackGraph()
    g.add_node(GraphNode(node_id="a", node_type=NodeType.FINDING, label="sqli error confirmed"))
    g.set_status("a", NodeStatus.CONFIRMED, evidence_ids=["ev_x"])
    chains = suggest_chains(g)
    assert any("sqli" in c.label for c in chains)
