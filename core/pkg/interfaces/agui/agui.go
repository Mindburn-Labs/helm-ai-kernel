// Package agui implements the Autonomous Generative UI (AGUI) protocol.
//
// Per KERNEL_INTEGRATION §3, AGUI defines a 3-tier trust model for UI components
// generated or mediated by the kernel:
// 1. Static: Pre-approved, deterministic components (e.g. Buttons, Lists).
// 2. Declarative: Data-driven components with strict schemas (e.g. Dashboards).
// 3. Sandbox: Untrusted/Dynamic components running in isolation (e.g. MCP GenUI).
package agui

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// UIProtocolTier defines the trust level and execution model for a UI component.
type UIProtocolTier string

const (
	// ProtocolStatic — deterministic, pre-compiled components.
	// Highest trust, lowest flexibility.
	ProtocolStatic UIProtocolTier = "STATIC"

	// ProtocolDeclarative — schema-driven components.
	// High trust, moderate flexibility.
	ProtocolDeclarative UIProtocolTier = "DECLARATIVE"

	// ProtocolSandbox — fully dynamic/generative components.
	// Lowest trust, highest flexibility. Requires strict isolation.
	ProtocolSandbox UIProtocolTier = "SANDBOX"
)

// UIComponentDefinition defines a registered UI component.
type UIComponentDefinition struct {
	ID          string         `json:"id"`
	Protocol    UIProtocolTier `json:"protocol"`
	Schema      string         `json:"schema,omitempty"` // JSON Schema for props
	TrustLevel  int            `json:"trust_level"`      // 0-100
	Description string         `json:"description"`
}

// RenderRequest represents an intent to render a UI component.
type RenderRequest struct {
	ComponentID string                 `json:"component_id"`
	Props       map[string]interface{} `json:"props"`
	Context     map[string]interface{} `json:"context"`
	RequesterID string                 `json:"requester_id"`
}

// RenderReceipt confirms that a render request was approved and processed.
type RenderReceipt struct {
	RenderID    string         `json:"render_id"`
	ComponentID string         `json:"component_id"`
	Protocol    UIProtocolTier `json:"protocol"`
	IssuedAt    time.Time      `json:"issued_at"`
	Signature   string         `json:"signature"` // Kernel signature
}

// ComponentRegistry manages the whitelist of allowed UI components.
type ComponentRegistry struct {
	mu         sync.RWMutex
	components map[string]UIComponentDefinition
}

// NewComponentRegistry creates a new registry.
func NewComponentRegistry() *ComponentRegistry {
	return &ComponentRegistry{
		components: make(map[string]UIComponentDefinition),
	}
}

// Register adds a component definition to the registry.
func (r *ComponentRegistry) Register(def UIComponentDefinition) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.components[def.ID]; exists {
		return fmt.Errorf("component already registered: %s", def.ID)
	}
	r.components[def.ID] = def
	return nil
}

// Get retrieves a component definition.
func (r *ComponentRegistry) Get(id string) (UIComponentDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.components[id]
	return def, ok
}

// AGUIKernel mediates UI rendering requests.
type AGUIKernel struct {
	registry *ComponentRegistry
	signer   crypto.Signer
}

// NewAGUIKernel creates a new kernel mediator.
func NewAGUIKernel(registry *ComponentRegistry, signer crypto.Signer) *AGUIKernel {
	return &AGUIKernel{registry: registry, signer: signer}
}

// RequestRender validates and authorizes a render request.
func (k *AGUIKernel) RequestRender(ctx context.Context, req RenderRequest) (*RenderReceipt, error) {
	if k.registry == nil {
		return nil, fmt.Errorf("registry not configured (fail-closed)")
	}
	if k.signer == nil {
		return nil, fmt.Errorf("signer not configured (fail-closed)")
	}

	// 1. Validate Component Existence
	def, exists := k.registry.Get(req.ComponentID)
	if !exists {
		return nil, fmt.Errorf("unknown component: %s", req.ComponentID)
	}

	// 2. Protocol-Specific Validation
	switch def.Protocol {
	case ProtocolStatic:
		// Static components are always allowed if registered.
	case ProtocolDeclarative:
		if req.Props == nil {
			return nil, fmt.Errorf("props required for declarative component")
		}
		if def.Schema == "" {
			return nil, fmt.Errorf("schema required for declarative component")
		}

		c := jsonschema.NewCompiler()
		c.Draft = jsonschema.Draft2020
		schemaURL := "https://helm.schemas.local/agui/component.schema.json"
		if err := c.AddResource(schemaURL, strings.NewReader(def.Schema)); err != nil {
			return nil, fmt.Errorf("failed to load schema: %w", err)
		}
		schema, err := c.Compile(schemaURL)
		if err != nil {
			return nil, fmt.Errorf("failed to compile schema: %w", err)
		}
		if err := schema.Validate(req.Props); err != nil {
			return nil, fmt.Errorf("schema validation failed: %w", err)
		}
	case ProtocolSandbox:
		// Sandbox components require explicit trust/context check.
		// For MVP, we check a simplified trust level.
		if def.TrustLevel < 50 {
			return nil, fmt.Errorf("insufficient trust for sandbox execution: %d < 50", def.TrustLevel)
		}
	default:
		return nil, fmt.Errorf("unknown protocol: %s", def.Protocol)
	}

	// 3. Issue Receipt
	issuedAt := time.Now().UTC()
	rcpt := &RenderReceipt{
		RenderID:    fmt.Sprintf("rnd-%d", time.Now().UnixNano()),
		ComponentID: req.ComponentID,
		Protocol:    def.Protocol,
		IssuedAt:    issuedAt, // Should use authority clock
	}
	sigPayload := fmt.Sprintf("%s|%s|%s|%s", rcpt.RenderID, rcpt.ComponentID, rcpt.Protocol, rcpt.IssuedAt.Format(time.RFC3339Nano))
	sig, err := k.signer.Sign([]byte(sigPayload))
	if err != nil {
		return nil, fmt.Errorf("failed to sign receipt: %w", err)
	}
	rcpt.Signature = sig
	return rcpt, nil
}
