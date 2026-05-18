package repair

type Plan struct {
	LaunchID      string       `json:"launch_id"`
	KernelVerdict string       `json:"kernel_verdict"`
	Steps         []string     `json:"steps"`
	Diagnostics   []Diagnostic `json:"diagnostics"`
}

func EscalatedPlan(launchID string, diagnostics []Diagnostic) Plan {
	return Plan{
		LaunchID:      launchID,
		KernelVerdict: "ESCALATE",
		Steps: []string{
			"inspect launch session",
			"verify policy, sandbox, MCP, secret, and healthcheck state",
			"require operator approval before any side effect",
		},
		Diagnostics: diagnostics,
	}
}
