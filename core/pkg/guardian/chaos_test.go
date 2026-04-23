package guardian

import (
	"context"
	"strings"
	"testing"

	pkg_artifact "github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
)

// Chaos tests for the Guardian pipeline fail-closed invariant.
//
// Named TestChaos_<scenario> to match chaos-drill.yml.

// TestChaos_guardian_panic_path_fails_closed asserts that if the Guardian
// encounters a state it cannot handle, the result is DENY — never ALLOW.
//
// The invariant under test: there is no execution path through
// EvaluateDecision where an error or unexpected state produces an ALLOW
// verdict. Fail-closed means DENY is the default for EVERY fault.
//
// We exercise this by sending a DecisionRequest with deliberately
// pathological inputs through a minimal Guardian (no optional gates wired)
// and asserting the result is always DENY or error — never ALLOW.
func TestChaos_guardian_panic_path_fails_closed(t *testing.T) {
	mockStore := NewMockStore()
	registry := pkg_artifact.NewRegistry(mockStore, nil)
	signer := &MockSigner{}
	ruleGraph := prg.NewGraph()
	// Intentionally empty rule graph — no permissive rule → default-deny.

	g := NewGuardian(signer, ruleGraph, registry)

	tests := []struct {
		name string
		req  DecisionRequest
	}{
		{
			name: "empty_request",
			req:  DecisionRequest{},
		},
		{
			name: "nil_context",
			req: DecisionRequest{
				Principal: "chaos-agent",
				Action:    "READ",
				Resource:  "file:///etc/shadow",
				Context:   nil,
			},
		},
		{
			name: "unknown_action",
			req: DecisionRequest{
				Principal: "chaos-agent",
				Action:    "OBLITERATE",
				Resource:  "universe://everything",
				Context:   map[string]interface{}{},
			},
		},
		{
			name: "oversized_resource",
			req: DecisionRequest{
				Principal: "chaos-agent",
				Action:    "READ",
				Resource:  strings.Repeat("A", 1<<16), // 64 KiB resource path
				Context:   map[string]interface{}{},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := g.EvaluateDecision(context.Background(), tc.req)

			// Acceptable outcomes: (1) error returned, or (2) DENY verdict.
			// Unacceptable: ALLOW on ANY pathological input.
			if err != nil {
				// Error is an acceptable fail-closed outcome.
				return
			}
			if resp == nil {
				t.Fatal("CHAOS INVARIANT BROKEN: nil response without error — ambiguous state")
			}
			if resp.Verdict == "ALLOW" || resp.Verdict == "APPROVED" {
				t.Fatalf("CHAOS INVARIANT BROKEN: pathological input %q produced ALLOW verdict: %+v",
					tc.name, resp)
			}
			// DENY, DENIED, ESCALATE, or any non-ALLOW verdict is acceptable.
		})
	}
}
