package controls

import (
	"testing"
)

func TestGraph_InitEmpty(t *testing.T) {
	g := NewGraph()
	nodes, edges := g.Stats()
	if nodes != 0 || edges != 0 {
		t.Errorf("new graph should be empty, got %d nodes, %d edges", nodes, edges)
	}
}

func TestAddNode_ValidNode(t *testing.T) {
	g := NewGraph()
	err := g.AddNode(&Node{ID: "n1", Type: NodeObligation, Label: "Obligation 1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes, _ := g.Stats()
	if nodes != 1 {
		t.Error("expected 1 node")
	}
}

func TestAddNode_NilNodeError(t *testing.T) {
	g := NewGraph()
	if err := g.AddNode(nil); err == nil {
		t.Error("expected error for nil node")
	}
}

func TestAddNode_EmptyIDError(t *testing.T) {
	g := NewGraph()
	if err := g.AddNode(&Node{ID: ""}); err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestAddEdge_ValidEdge(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "n1", Type: NodeControl})
	g.AddNode(&Node{ID: "n2", Type: NodeObligation})
	err := g.AddEdge(&Edge{ID: "e1", Type: EdgeSatisfies, FromID: "n1", ToID: "n2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddEdge_NoFromNodeError(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "n2", Type: NodeObligation})
	err := g.AddEdge(&Edge{ID: "e1", FromID: "missing", ToID: "n2"})
	if err == nil {
		t.Error("expected error for missing from node")
	}
}

func TestAddEdge_NoToNodeError(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "n1", Type: NodeControl})
	err := g.AddEdge(&Edge{ID: "e1", FromID: "n1", ToID: "missing"})
	if err == nil {
		t.Error("expected error for missing to node")
	}
}

func TestAddEdge_NilEdgeError(t *testing.T) {
	g := NewGraph()
	if err := g.AddEdge(nil); err == nil {
		t.Error("expected error for nil edge")
	}
}

func TestGetNode_FoundAndMissing(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "n1", Type: NodeCheck, Label: "Check 1"})
	n, ok := g.GetNode("n1")
	if !ok || n.Label != "Check 1" {
		t.Error("expected to find node n1")
	}
	_, ok = g.GetNode("missing")
	if ok {
		t.Error("expected not to find missing node")
	}
}

func TestGetOutbound_ReturnsEdges(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "n1", Type: NodeObligation})
	g.AddNode(&Node{ID: "n2", Type: NodeEvidenceType})
	g.AddNode(&Node{ID: "n3", Type: NodeCheck})
	g.AddEdge(&Edge{ID: "e1", Type: EdgeRequires, FromID: "n1", ToID: "n2"})
	g.AddEdge(&Edge{ID: "e2", Type: EdgeRequires, FromID: "n1", ToID: "n3"})
	edges := g.GetOutbound("n1")
	if len(edges) != 2 {
		t.Errorf("expected 2 outbound edges, got %d", len(edges))
	}
}

func TestFindSatisfyingControls_MultipleControls(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "ctrl1", Type: NodeControl, Label: "Control A"})
	g.AddNode(&Node{ID: "ctrl2", Type: NodeControl, Label: "Control B"})
	g.AddNode(&Node{ID: "obl1", Type: NodeObligation})
	g.AddEdge(&Edge{ID: "e1", Type: EdgeSatisfies, FromID: "ctrl1", ToID: "obl1"})
	g.AddEdge(&Edge{ID: "e2", Type: EdgeSatisfies, FromID: "ctrl2", ToID: "obl1"})
	ctrls := g.FindSatisfyingControls("obl1")
	if len(ctrls) != 2 {
		t.Errorf("expected 2 satisfying controls, got %d", len(ctrls))
	}
}

func TestFindRequiredEvidence_ReturnsEvidence(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "obl1", Type: NodeObligation})
	g.AddNode(&Node{ID: "ev1", Type: NodeEvidenceType, Label: "Audit Log"})
	g.AddEdge(&Edge{ID: "e1", Type: EdgeRequires, FromID: "obl1", ToID: "ev1"})
	evs := g.FindRequiredEvidence("obl1")
	if len(evs) != 1 || evs[0].Label != "Audit Log" {
		t.Error("expected 1 required evidence type 'Audit Log'")
	}
}

func TestFindConflicts_DetectsConflictEdge(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "c1", Type: NodeControl})
	g.AddNode(&Node{ID: "c2", Type: NodeControl})
	g.AddEdge(&Edge{ID: "e1", Type: EdgeConflictWith, FromID: "c1", ToID: "c2"})
	conflicts := g.FindConflicts()
	if len(conflicts) != 1 {
		t.Errorf("expected 1 conflict, got %d", len(conflicts))
	}
}

func TestFindConflicts_NoConflicts(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "c1", Type: NodeControl})
	g.AddNode(&Node{ID: "o1", Type: NodeObligation})
	g.AddEdge(&Edge{ID: "e1", Type: EdgeSatisfies, FromID: "c1", ToID: "o1"})
	conflicts := g.FindConflicts()
	if len(conflicts) != 0 {
		t.Error("expected 0 conflicts")
	}
}

func TestStats_ReturnsCorrectCounts(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "n1", Type: NodeObligation})
	g.AddNode(&Node{ID: "n2", Type: NodeControl})
	g.AddEdge(&Edge{ID: "e1", Type: EdgeSatisfies, FromID: "n2", ToID: "n1"})
	nodes, edges := g.Stats()
	if nodes != 2 || edges != 1 {
		t.Errorf("expected 2 nodes and 1 edge, got %d nodes and %d edges", nodes, edges)
	}
}
