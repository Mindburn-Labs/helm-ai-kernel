package scenarios

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity"
)

// Scenario 3: Agent Impersonation via Shared Secret + Email
//
// Threat: A malicious agent reuses another agent's credentials to
// impersonate it and access privileged operations.
// Expected: DENY with IDENTITY_ISOLATION_VIOLATION.
func TestAgentImpersonation_SharedCredentialDenied(t *testing.T) {
	ic := identity.NewIsolationChecker()

	// Legitimate agent binds its credential
	err := ic.ValidateAgentIdentity("agent-production", "cred-hash-production-abcdef", "session-1")
	if err != nil {
		t.Fatalf("legitimate binding should succeed: %v", err)
	}

	// Attacker agent tries to reuse the same credential
	err = ic.ValidateAgentIdentity("agent-attacker", "cred-hash-production-abcdef", "session-2")
	if err == nil {
		t.Fatal("credential reuse by different agent should be denied")
	}

	violation, ok := err.(*identity.IsolationViolationError)
	if !ok {
		t.Fatalf("error type = %T, want *IsolationViolationError", err)
	}
	if violation.BoundPrincipal != "agent-production" {
		t.Errorf("bound principal = %s, want agent-production", violation.BoundPrincipal)
	}
	if violation.AttemptingPrincipal != "agent-attacker" {
		t.Errorf("attempting = %s, want agent-attacker", violation.AttemptingPrincipal)
	}

	// Verify violation is recorded in audit trail
	violations := ic.Violations()
	if len(violations) != 1 {
		t.Fatalf("violation count = %d, want 1", len(violations))
	}
}

func TestAgentImpersonation_PrivilegedInvokeClassification(t *testing.T) {
	et := contracts.LookupEffectType(contracts.EffectTypeAgentInvokePrivileged)
	if et == nil {
		t.Fatal("AGENT_INVOKE_PRIVILEGED not found")
	}

	rc := contracts.EffectRiskClass(contracts.EffectTypeAgentInvokePrivileged)
	if rc != "E3" {
		t.Errorf("risk class = %s, want E3", rc)
	}

	if et.DefaultApprovalLevel != "single_human" {
		t.Errorf("approval = %s, want single_human", et.DefaultApprovalLevel)
	}
}
