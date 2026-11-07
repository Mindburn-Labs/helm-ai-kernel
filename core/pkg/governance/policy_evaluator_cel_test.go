package governance

import ()

func celPolicyModule(policy, name, version string) ModuleBundle {
	if name == "" {
		name = "acme.reader"
	}
	if version == "" {
		version = "1.2.3"
	}
	return ModuleBundle{
		ID: "module-1",
		Manifest: map[string]any{
			"name":    name,
			"version": version,
		},
		Policy: policy,
	}
}
