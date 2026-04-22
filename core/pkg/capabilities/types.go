package capabilities

import (
	"context"
)

// EffectType categorizes the specific side-effect.
type EffectType string

// Capability represents a function or tool the system can invoke.
type Capability struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	EffectClass string            `json:"effect_class"`          // e.g. "E1", "E3"
	Constraints map[string]string `json:"constraints,omitempty"` // e.g. "max_amount": "50.00"
	Effects     []EffectType      `json:"effects"`
	Inputs      SchemaDefinition  `json:"inputs"`
	Outputs     SchemaDefinition  `json:"outputs"`
	Signature   string            `json:"signature"` // Hash of Name+Inputs+Outputs

	// Handler is the runtime implementation.
	// In a real system, this is loaded from WASM/Plugin.
	Handler func(context.Context, map[string]interface{}) (map[string]interface{}, error) `json:"-"`
}

type SchemaDefinition struct {
	Fields map[string]string `json:"fields"` // Key: FieldName, Value: Type (e.g. "string", "int")
}

// ToolCatalog is the registry of available capabilities.
type ToolCatalog struct {
	tools map[string]Capability
}

func NewToolCatalog() *ToolCatalog {
	return &ToolCatalog{
		tools: make(map[string]Capability),
	}
}

// Add registers a fully functional Capability (with Handler).
func (c *ToolCatalog) Add(cap Capability) {
	c.tools[cap.ID] = cap
}

func (c *ToolCatalog) Get(id string) (Capability, bool) {
	cap, ok := c.tools[id]
	return cap, ok
}
