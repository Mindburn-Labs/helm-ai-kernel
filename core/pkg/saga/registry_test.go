package saga

import (
	"sort"
	"testing"
	"time"
)

func TestReversibilityRegistry_Register(t *testing.T) {
	reg := NewReversibilityRegistry()

	err := reg.Register(ActionRegistration{
		ActionID:       "deploy",
		Reversible:     true,
		CompensatingID: "undeploy",
		MaxRetries:     3,
		Timeout:        30 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, ok := reg.Lookup("deploy")
	if !ok {
		t.Fatal("expected to find registered action")
	}
	if got.ActionID != "deploy" {
		t.Errorf("expected ActionID 'deploy', got %s", got.ActionID)
	}
	if got.CompensatingID != "undeploy" {
		t.Errorf("expected CompensatingID 'undeploy', got %s", got.CompensatingID)
	}
	if got.MaxRetries != 3 {
		t.Errorf("expected MaxRetries 3, got %d", got.MaxRetries)
	}
}

func TestReversibilityRegistry_Lookup(t *testing.T) {
	reg := NewReversibilityRegistry()

	// Not found
	_, ok := reg.Lookup("nonexistent")
	if ok {
		t.Error("expected action not found")
	}

	// Register and find
	err := reg.Register(ActionRegistration{
		ActionID:   "create",
		Reversible: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, ok := reg.Lookup("create")
	if !ok {
		t.Fatal("expected to find registered action")
	}
	if got.ActionID != "create" {
		t.Errorf("expected 'create', got %s", got.ActionID)
	}
}

func TestReversibilityRegistry_IsReversible(t *testing.T) {
	reg := NewReversibilityRegistry()

	// Reversible action
	err := reg.Register(ActionRegistration{
		ActionID:       "deploy",
		Reversible:     true,
		CompensatingID: "undeploy",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reg.IsReversible("deploy") {
		t.Error("expected deploy to be reversible")
	}

	// Non-reversible action
	err = reg.Register(ActionRegistration{
		ActionID:   "notify",
		Reversible: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if reg.IsReversible("notify") {
		t.Error("expected notify to not be reversible")
	}

	// Unknown action
	if reg.IsReversible("unknown") {
		t.Error("expected unknown action to not be reversible")
	}
}

func TestReversibilityRegistry_EmptyActionID(t *testing.T) {
	reg := NewReversibilityRegistry()

	err := reg.Register(ActionRegistration{
		ActionID: "",
	})
	if err == nil {
		t.Fatal("expected error for empty action ID")
	}
}

func TestReversibilityRegistry_ListActions(t *testing.T) {
	reg := NewReversibilityRegistry()

	// Empty registry
	ids := reg.ListActions()
	if len(ids) != 0 {
		t.Errorf("expected 0 actions, got %d", len(ids))
	}

	// Register some actions
	for _, id := range []string{"deploy", "create", "notify"} {
		err := reg.Register(ActionRegistration{ActionID: id, Reversible: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	ids = reg.ListActions()
	if len(ids) != 3 {
		t.Fatalf("expected 3 actions, got %d", len(ids))
	}

	// Sort for deterministic comparison (map iteration order is random)
	sort.Strings(ids)
	expected := []string{"create", "deploy", "notify"}
	for i, id := range ids {
		if id != expected[i] {
			t.Errorf("index %d: expected %s, got %s", i, expected[i], id)
		}
	}
}
