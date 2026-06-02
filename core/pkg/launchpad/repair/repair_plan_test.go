package repair

import "testing"

func TestEscalatedPlan(t *testing.T) {
	diagnostics := []Diagnostic{
		{Code: "ERR_REPAIR_REQUIRES_OPERATOR_APPROVAL", Message: "approval required"},
		{Code: "ERR_LAUNCH_ESCALATED", Message: "launch escalated"},
	}

	plan := EscalatedPlan("launch-1", diagnostics)

	if plan.LaunchID != "launch-1" {
		t.Fatalf("LaunchID = %q", plan.LaunchID)
	}
	if plan.KernelVerdict != "ESCALATE" {
		t.Fatalf("KernelVerdict = %q", plan.KernelVerdict)
	}
	if len(plan.Steps) != 3 {
		t.Fatalf("expected three repair steps, got %#v", plan.Steps)
	}
	wantSteps := []string{
		"inspect launch session",
		"verify policy, sandbox, MCP, secret, and healthcheck state",
		"require operator approval before any side effect",
	}
	for i, want := range wantSteps {
		if plan.Steps[i] != want {
			t.Fatalf("step %d = %q, want %q", i, plan.Steps[i], want)
		}
	}
	if len(plan.Diagnostics) != len(diagnostics) {
		t.Fatalf("diagnostics length = %d", len(plan.Diagnostics))
	}
	for i := range diagnostics {
		if plan.Diagnostics[i] != diagnostics[i] {
			t.Fatalf("diagnostic %d = %#v, want %#v", i, plan.Diagnostics[i], diagnostics[i])
		}
	}
}
