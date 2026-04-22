package firewall

import (
	"context"
	"sync"
	"testing"
)

type testDispatcher struct{}

func (d *testDispatcher) Dispatch(ctx context.Context, toolName string, params map[string]any) (any, error) {
	return map[string]any{"tool": toolName, "params": params}, nil
}

func TestPolicyFirewall_BlockUnknown(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	if err := fw.AllowTool("other_tool", ""); err != nil {
		t.Fatalf("allow tool failed: %v", err)
	}

	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "unknown_tool", nil)
	if err == nil {
		t.Error("Expected error for unknown tool, got nil")
	}
}

func TestPolicyFirewall_AllowKnown(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	if err := fw.AllowTool("known_tool", "{}"); err != nil {
		t.Fatalf("allow tool failed: %v", err)
	}

	res, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "known_tool", map[string]any{"foo": "bar"})
	if err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
	out, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result type: %T", res)
	}
	if out["tool"] != "known_tool" {
		t.Errorf("unexpected tool: %v", out["tool"])
	}
}

func TestPolicyFirewall_NilDispatcher(t *testing.T) {
	// Fail-closed: no dispatcher → error
	fw := NewPolicyFirewall(nil)
	if err := fw.AllowTool("tool", ""); err != nil {
		t.Fatal(err)
	}
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "tool", nil)
	if err == nil {
		t.Fatal("Expected fail-closed error with nil dispatcher")
	}
}

func TestPolicyFirewall_SchemaValidation(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	schema := `{
		"type": "object",
		"properties": {
			"name": {"type": "string"},
			"count": {"type": "integer"}
		},
		"required": ["name"]
	}`
	if err := fw.AllowTool("validated_tool", schema); err != nil {
		t.Fatalf("allow tool with schema failed: %v", err)
	}

	// Valid params
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "validated_tool", map[string]any{
		"name":  "test",
		"count": 5,
	})
	if err != nil {
		t.Errorf("Valid params should pass: %v", err)
	}
}

func TestPolicyFirewall_SchemaValidationReject(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	schema := `{
		"type": "object",
		"properties": {
			"name": {"type": "string"}
		},
		"required": ["name"]
	}`
	if err := fw.AllowTool("strict_tool", schema); err != nil {
		t.Fatal(err)
	}

	// Missing required field "name"
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "strict_tool", map[string]any{
		"other": "value",
	})
	if err == nil {
		t.Fatal("Expected schema validation error for missing required field")
	}
}

func TestPolicyFirewall_MissingParams(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	schema := `{"type": "object", "required": ["x"]}`
	if err := fw.AllowTool("needs_params", schema); err != nil {
		t.Fatal(err)
	}

	// Nil params with schema → should be rejected
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "needs_params", nil)
	if err == nil {
		t.Fatal("Expected error for nil params with schema requirement")
	}
}

func TestPolicyFirewall_EmptySchemaPassthrough(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	// Empty schema string = no validation
	if err := fw.AllowTool("no_schema", ""); err != nil {
		t.Fatal(err)
	}

	// Any params should pass
	res, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "no_schema", map[string]any{"anything": true})
	if err != nil {
		t.Errorf("Tool with no schema should accept any params: %v", err)
	}
	if res == nil {
		t.Error("Expected non-nil result")
	}
}

func TestPolicyFirewall_SchemaCompileError(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	// Invalid JSON Schema
	err := fw.AllowTool("bad_schema", `{"type": "not_a_real_type"}`)
	// Depending on the library, this may or may not error at compile time.
	// But non-JSON should definitely error:
	err = fw.AllowTool("bad_json", `{not valid json`)
	if err == nil {
		t.Error("Expected error for invalid JSON schema")
	}
}

func TestPolicyFirewall_MultipleTools(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	if err := fw.AllowTool("tool_a", ""); err != nil {
		t.Fatal(err)
	}
	if err := fw.AllowTool("tool_b", `{"type":"object"}`); err != nil {
		t.Fatal(err)
	}

	// tool_a works
	if _, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "tool_a", nil); err != nil {
		t.Errorf("tool_a should work: %v", err)
	}
	// tool_b works
	if _, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "tool_b", map[string]any{}); err != nil {
		t.Errorf("tool_b should work: %v", err)
	}
	// tool_c is blocked
	if _, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "tool_c", nil); err == nil {
		t.Error("tool_c should be blocked")
	}
}

func TestPolicyFirewall_ConcurrentAccess(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	if err := fw.AllowTool("concurrent_tool", ""); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = fw.CallTool(context.Background(), PolicyInputBundle{
				ActorID:   "user:1",
				SessionID: "sess-1",
			}, "concurrent_tool", map[string]any{"i": 1})
		}()
	}
	wg.Wait()
}

func TestPolicyFirewall_PolicyInputBundle(t *testing.T) {
	// Verify PolicyInputBundle fields are properly constructed
	bundle := PolicyInputBundle{
		ActorID:   "user:alice",
		Role:      "admin",
		SessionID: "sess-123",
	}
	if bundle.ActorID != "user:alice" || bundle.Role != "admin" || bundle.SessionID != "sess-123" {
		t.Error("PolicyInputBundle fields not properly set")
	}
}
