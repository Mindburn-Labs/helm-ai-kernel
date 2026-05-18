package registry

type SubstrateSpec struct {
	ID               string            `json:"id" yaml:"id"`
	Name             string            `json:"name" yaml:"name"`
	Kind             string            `json:"kind" yaml:"kind"`
	Availability     string            `json:"availability" yaml:"availability"`
	DefaultDryRun    bool              `json:"default_dry_run" yaml:"default_dry_run"`
	PolicyPack       string            `json:"policy_pack" yaml:"policy_pack"`
	Provisioner      string            `json:"provisioner" yaml:"provisioner"`
	SupportsTeardown bool              `json:"supports_teardown" yaml:"supports_teardown"`
	RequiresApproval bool              `json:"requires_approval" yaml:"requires_approval"`
	Network          NetworkPolicy     `json:"network" yaml:"network"`
	Filesystem       PolicyRef         `json:"filesystem" yaml:"filesystem"`
	Metadata         map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}
