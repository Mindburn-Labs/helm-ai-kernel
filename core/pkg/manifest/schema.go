package manifest

// Module defines the structure of a HELM Extension Module.
type Module struct {
	Name         string             `json:"name" yaml:"name"`
	Version      string             `json:"version" yaml:"version"`
	Description  string             `json:"description" yaml:"description"`
	Dependencies []string           `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	Capabilities []CapabilityConfig `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Policies     []PolicyConfig     `json:"policies,omitempty" yaml:"policies,omitempty"`
}

// CapabilityConfig describes a tool exposed by the modules.
type CapabilityConfig struct {
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description" yaml:"description"`
	ArgsSchema  string   `json:"args_schema" yaml:"args_schema"` // JSON Schema or simple description
	Permissions []string `json:"permissions,omitempty" yaml:"permissions,omitempty"`
}

// PolicyConfig describes a governance rule.
type PolicyConfig struct {
	Name        string `json:"name" yaml:"name"`
	RegoContent string `json:"rego_content" yaml:"rego_content"` // Inline Rego validation
	EnforcedOn  string `json:"enforced_on" yaml:"enforced_on"`   // "BeforeExecution", "AfterPlanning"
}

// Bundle represents a compiled, verified module ready for installation.
type Bundle struct {
	Manifest   Module `json:"manifest"`
	Signature  string `json:"signature"`   // Signed by the Author
	PowerDelta int    `json:"power_delta"` // Complexity Score
	CompiledAt string `json:"compiled_at"`
}
