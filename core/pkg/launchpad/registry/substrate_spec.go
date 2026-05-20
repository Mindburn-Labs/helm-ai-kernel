package registry

type SubstrateSpec struct {
	ID               string                `json:"id" yaml:"id"`
	Name             string                `json:"name" yaml:"name"`
	Kind             string                `json:"kind" yaml:"kind"`
	Availability     string                `json:"availability" yaml:"availability"`
	DefaultDryRun    bool                  `json:"default_dry_run" yaml:"default_dry_run"`
	PolicyPack       string                `json:"policy_pack" yaml:"policy_pack"`
	Provisioner      string                `json:"provisioner" yaml:"provisioner"`
	SupportsTeardown bool                  `json:"supports_teardown" yaml:"supports_teardown"`
	RequiresApproval bool                  `json:"requires_approval" yaml:"requires_approval"`
	Capabilities     SubstrateCapabilities `json:"capabilities" yaml:"capabilities"`
	Isolation        IsolationPolicy       `json:"isolation" yaml:"isolation"`
	Network          NetworkPolicy         `json:"network" yaml:"network"`
	Filesystem       PolicyRef             `json:"filesystem" yaml:"filesystem"`
	Metadata         map[string]string     `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

type IsolationPolicy struct {
	Mode              string   `json:"mode" yaml:"mode"`
	SupportedModes    []string `json:"supported_modes,omitempty" yaml:"supported_modes,omitempty"`
	HardenedModes     []string `json:"hardened_modes,omitempty" yaml:"hardened_modes,omitempty"`
	RuntimeClass      string   `json:"runtime_class,omitempty" yaml:"runtime_class,omitempty"`
	HostileAgentGrade bool     `json:"hostile_agent_grade" yaml:"hostile_agent_grade"`
}

type SubstrateCapabilities struct {
	IsolationStrength  string   `json:"isolation_strength" yaml:"isolation_strength"`
	NetworkEnforcement string   `json:"network_enforcement" yaml:"network_enforcement"`
	SecretMode         string   `json:"secret_mode" yaml:"secret_mode"`
	ReceiptSupport     string   `json:"receipt_support" yaml:"receipt_support"`
	TeardownProof      string   `json:"teardown_proof" yaml:"teardown_proof"`
	Status             string   `json:"status" yaml:"status"`
	Lifecycle          []string `json:"lifecycle" yaml:"lifecycle"`
}
