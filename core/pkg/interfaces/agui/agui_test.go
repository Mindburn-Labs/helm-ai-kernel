package agui

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

func newTestKernel(t *testing.T, reg *ComponentRegistry) *AGUIKernel {
	t.Helper()
	signer, err := crypto.NewEd25519Signer("test-agui")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	return NewAGUIKernel(reg, signer)
}

func TestComponentRegistry_Register(t *testing.T) {
	reg := NewComponentRegistry()
	def := UIComponentDefinition{
		ID:          "btn-primary",
		Protocol:    ProtocolStatic,
		Description: "Standard primary button",
	}

	if err := reg.Register(def); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if err := reg.Register(def); err == nil {
		t.Fatal("Expected error on duplicate registration")
	}

	retrieved, ok := reg.Get("btn-primary")
	if !ok {
		t.Fatal("Failed to retrieve registered component")
	}
	if retrieved.Protocol != ProtocolStatic {
		t.Errorf("Expected Static protocol, got %s", retrieved.Protocol)
	}
}

func TestAGUIKernel_RequestRender_Static(t *testing.T) {
	reg := NewComponentRegistry()
	reg.Register(UIComponentDefinition{
		ID:       "static-card",
		Protocol: ProtocolStatic,
	})
	kernel := newTestKernel(t, reg)

	req := RenderRequest{ComponentID: "static-card"}
	receipt, err := kernel.RequestRender(context.Background(), req)
	if err != nil {
		t.Fatalf("RequestRender failed: %v", err)
	}
	if receipt.Protocol != ProtocolStatic {
		t.Errorf("Expected Static protocol in receipt, got %s", receipt.Protocol)
	}
}

func TestAGUIKernel_RequestRender_Declarative(t *testing.T) {
	reg := NewComponentRegistry()
	reg.Register(UIComponentDefinition{
		ID:       "data-table",
		Protocol: ProtocolDeclarative,
		Schema: `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "rows": { "type": "integer" }
  },
  "required": ["rows"],
  "additionalProperties": false
}`,
	})
	kernel := newTestKernel(t, reg)

	// Missing props (should fail per stub logic)
	reqBad := RenderRequest{ComponentID: "data-table"}
	if _, err := kernel.RequestRender(context.Background(), reqBad); err == nil {
		t.Fatal("Expected error for missing props in declarative component")
	}

	// With props
	reqGood := RenderRequest{
		ComponentID: "data-table",
		Props:       map[string]interface{}{"rows": 10},
	}
	if _, err := kernel.RequestRender(context.Background(), reqGood); err != nil {
		t.Fatalf("RequestRender failed for valid declarative req: %v", err)
	}
}

func TestAGUIKernel_RequestRender_Sandbox(t *testing.T) {
	reg := NewComponentRegistry()
	reg.Register(UIComponentDefinition{
		ID:         "untrusted-widget",
		Protocol:   ProtocolSandbox,
		TrustLevel: 10,
	})
	reg.Register(UIComponentDefinition{
		ID:         "trusted-widget",
		Protocol:   ProtocolSandbox,
		TrustLevel: 90,
	})
	kernel := newTestKernel(t, reg)

	// Untrusted -> Reject
	if _, err := kernel.RequestRender(context.Background(), RenderRequest{ComponentID: "untrusted-widget"}); err == nil {
		t.Fatal("Expected reject for low trust sandbox component")
	}

	// Trusted -> Allow
	if _, err := kernel.RequestRender(context.Background(), RenderRequest{ComponentID: "trusted-widget"}); err != nil {
		t.Fatalf("Expected accept for high trust sandbox component: %v", err)
	}
}

func TestAGUIKernel_UnknownComponent(t *testing.T) {
	kernel := newTestKernel(t, NewComponentRegistry())
	if _, err := kernel.RequestRender(context.Background(), RenderRequest{ComponentID: "ghost"}); err == nil {
		t.Fatal("Expected error for unknown component")
	}
}
