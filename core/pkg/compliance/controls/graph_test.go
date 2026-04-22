package controls

import (
	"testing"
)

func TestNewGraph(t *testing.T) {
	g := NewGraph()
	if g == nil {
		t.Fatal("expected non-nil graph")
	}
	nodes, edges := g.Stats()
	if nodes != 0 || edges != 0 {
		t.Errorf("expected 0 nodes/edges, got %d/%d", nodes, edges)
	}
}

func TestAddNodeAndEdge(t *testing.T) {
	g := NewGraph()

	obligation := &Node{ID: "obl-1", Type: NodeObligation, Label: "MFA Required"}
	control := &Node{ID: "ctrl-1", Type: NodeControl, Label: "Implement MFA"}
	evidence := &Node{ID: "ev-1", Type: NodeEvidenceType, Label: "MFA Config Screenshot"}

	for _, n := range []*Node{obligation, control, evidence} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("AddNode(%s) failed: %v", n.ID, err)
		}
	}

	nodes, _ := g.Stats()
	if nodes != 3 {
		t.Errorf("expected 3 nodes, got %d", nodes)
	}

	// Add edges
	e1 := &Edge{ID: "e-1", Type: EdgeSatisfies, FromID: "ctrl-1", ToID: "obl-1"}
	e2 := &Edge{ID: "e-2", Type: EdgeRequires, FromID: "obl-1", ToID: "ev-1"}

	for _, e := range []*Edge{e1, e2} {
		if err := g.AddEdge(e); err != nil {
			t.Fatalf("AddEdge(%s) failed: %v", e.ID, err)
		}
	}

	_, edges := g.Stats()
	if edges != 2 {
		t.Errorf("expected 2 edges, got %d", edges)
	}
}

func TestAddEdgeMissingNode(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "n1", Type: NodeObligation})

	err := g.AddEdge(&Edge{ID: "e1", FromID: "n1", ToID: "nonexistent"})
	if err == nil {
		t.Error("expected error for missing 'to' node")
	}

	err = g.AddEdge(&Edge{ID: "e2", FromID: "nonexistent", ToID: "n1"})
	if err == nil {
		t.Error("expected error for missing 'from' node")
	}
}

func TestAddInvalid(t *testing.T) {
	g := NewGraph()

	if err := g.AddNode(nil); err == nil {
		t.Error("expected error for nil node")
	}
	if err := g.AddNode(&Node{}); err == nil {
		t.Error("expected error for empty node ID")
	}
	if err := g.AddEdge(nil); err == nil {
		t.Error("expected error for nil edge")
	}
	if err := g.AddEdge(&Edge{}); err == nil {
		t.Error("expected error for empty edge ID")
	}
}

func TestFindSatisfyingControls(t *testing.T) {
	g := NewGraph()

	g.AddNode(&Node{ID: "obl-1", Type: NodeObligation})
	g.AddNode(&Node{ID: "ctrl-1", Type: NodeControl, Label: "Control A"})
	g.AddNode(&Node{ID: "ctrl-2", Type: NodeControl, Label: "Control B"})
	g.AddNode(&Node{ID: "ctrl-3", Type: NodeControl, Label: "Unrelated"})

	g.AddEdge(&Edge{ID: "e1", Type: EdgeSatisfies, FromID: "ctrl-1", ToID: "obl-1"})
	g.AddEdge(&Edge{ID: "e2", Type: EdgeSatisfies, FromID: "ctrl-2", ToID: "obl-1"})
	g.AddEdge(&Edge{ID: "e3", Type: EdgeMitigates, FromID: "ctrl-3", ToID: "obl-1"})

	controls := g.FindSatisfyingControls("obl-1")
	if len(controls) != 2 {
		t.Errorf("expected 2 satisfying controls, got %d", len(controls))
	}
}

func TestFindRequiredEvidence(t *testing.T) {
	g := NewGraph()

	g.AddNode(&Node{ID: "obl-1", Type: NodeObligation})
	g.AddNode(&Node{ID: "ev-1", Type: NodeEvidenceType, Label: "Audit Log"})
	g.AddNode(&Node{ID: "ev-2", Type: NodeEvidenceType, Label: "Config Dump"})

	g.AddEdge(&Edge{ID: "e1", Type: EdgeRequires, FromID: "obl-1", ToID: "ev-1"})
	g.AddEdge(&Edge{ID: "e2", Type: EdgeRequires, FromID: "obl-1", ToID: "ev-2"})

	evidence := g.FindRequiredEvidence("obl-1")
	if len(evidence) != 2 {
		t.Errorf("expected 2 evidence requirements, got %d", len(evidence))
	}
}

func TestFindConflicts(t *testing.T) {
	g := NewGraph()

	g.AddNode(&Node{ID: "ctrl-1", Type: NodeControl})
	g.AddNode(&Node{ID: "ctrl-2", Type: NodeControl})

	g.AddEdge(&Edge{ID: "conflict-1", Type: EdgeConflictWith, FromID: "ctrl-1", ToID: "ctrl-2"})

	conflicts := g.FindConflicts()
	if len(conflicts) != 1 {
		t.Errorf("expected 1 conflict, got %d", len(conflicts))
	}
}

func TestGetOutbound(t *testing.T) {
	g := NewGraph()

	g.AddNode(&Node{ID: "n1", Type: NodeObligation})
	g.AddNode(&Node{ID: "n2", Type: NodeControl})
	g.AddNode(&Node{ID: "n3", Type: NodeEvidenceType})

	g.AddEdge(&Edge{ID: "e1", Type: EdgeRequires, FromID: "n1", ToID: "n2"})
	g.AddEdge(&Edge{ID: "e2", Type: EdgeRequires, FromID: "n1", ToID: "n3"})

	outbound := g.GetOutbound("n1")
	if len(outbound) != 2 {
		t.Errorf("expected 2 outbound edges, got %d", len(outbound))
	}

	outbound2 := g.GetOutbound("n2")
	if len(outbound2) != 0 {
		t.Errorf("expected 0 outbound edges from n2, got %d", len(outbound2))
	}
}

func TestGetNode(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "test-node", Type: NodeCheck, Label: "Test"})

	n, ok := g.GetNode("test-node")
	if !ok {
		t.Fatal("expected to find node")
	}
	if n.Label != "Test" {
		t.Errorf("expected label 'Test', got %s", n.Label)
	}

	_, ok = g.GetNode("missing")
	if ok {
		t.Error("expected not to find missing node")
	}
}
