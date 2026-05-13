package guardian

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

// FuzzEvaluateDecision fuzzes the Guardian decision evaluation.
// Invariants:
//   - Must never panic on any input
//   - Must always return a signed DecisionRecord or an error
//   - Verdict must be ALLOW, DENY, or ESCALATE
func FuzzEvaluateDecision(f *testing.F) {
	f.Add("agent-1", "EXECUTE_TOOL", "safe-tool")
	f.Add("", "EXECUTE_TOOL", "unknown-tool")
	f.Add("agent-x", "", "")
	f.Add("agent-1", "INFRA_DESTROY", "production-db")
	f.Add("agent-1", "SEND_EMAIL", "user@example.com")
	f.Add("../../etc/passwd", "EXECUTE_TOOL", "; rm -rf /")
	f.Add("agent-1", "EXECUTE_TOOL", "safe-tool\x00injected")

	signer, err := crypto.NewEd25519Signer("fuzz-key")
	if err != nil {
		f.Fatal(err)
	}
	graph := prg.NewGraph()
	_ = graph.AddRule("safe-tool", prg.RequirementSet{ID: "allow-safe", Logic: prg.AND})
	g := NewGuardian(signer, graph, nil)

	f.Fuzz(func(t *testing.T, principal, action, resource string) {
		req := DecisionRequest{
			Principal: principal,
			Action:    action,
			Resource:  resource,
		}

		decision, err := g.EvaluateDecision(context.Background(), req)
		if err != nil {
			return // errors are acceptable
		}

		if decision == nil {
			t.Fatal("nil decision without error")
		}

		// Verdict must be canonical
		switch decision.Verdict {
		case "ALLOW", "DENY", "ESCALATE":
			// valid
		default:
			t.Fatalf("non-canonical verdict: %q", decision.Verdict)
		}

		// Signature must be non-empty
		if decision.Signature == "" {
			t.Fatal("unsigned decision returned")
		}
	})
}
