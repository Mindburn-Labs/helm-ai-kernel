package negative

import (
	"context"
	"fmt"
	"strings"

	pkg_artifact "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/firewall"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/identity"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

// seed is fixed so a roster hash, a decision id derivation, or a signature
// never varies run to run. Nothing here is a real key.
var seed = []byte("helm-negative-vector-runner-seed")

func newGuardian(graph *prg.Graph, opts ...guardian.GuardianOption) (*guardian.Guardian, error) {
	signer, err := crypto.NewEd25519SignerFromSeed(seed, "negative-vector-runner")
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	return guardian.NewGuardian(signer, graph, (*pkg_artifact.Registry)(nil), opts...), nil
}

// DefaultCases returns every vector that a Guardian can be driven into today.
//
// It is deliberately short. Of the 43 catalog vectors, most name a gate that
// is not injected on any production path, and eleven name a reason code with
// no producer anywhere in the tree — those cannot pass regardless of harness,
// and pretending otherwise is what a stub PDP would let you do (it echoes any
// reason code verbatim, so a fake backend could make all 43 "pass" while
// testing only the plumbing). Every case below drives a real gate.
func DefaultCases() []Case {
	return []Case{
		casePolicyNotReady(),
		casePDPOutage(),
		caseMissingCredentials(),
		caseBlockedEgress(),
	}
}

// casePolicyNotReady drives the Proof Requirement Graph with no rule for the
// requested action.
//
// The vector's Trigger says "policy bundle absent or not initialized at the
// PEP", which is the snapshot path and emits POLICY_NOT_READY. The vector's
// declared ExpectedReasonCode is NO_POLICY_DEFINED, which is the empty-graph
// path. The catalog contradicts itself; this harness satisfies the declared
// expectation, which is the machine-readable half.
func casePolicyNotReady() Case {
	return Case{
		VectorID: "policy-not-ready",
		Build: func() (*guardian.Guardian, guardian.DecisionRequest, error) {
			guard, err := newGuardian(prg.NewGraph())
			if err != nil {
				return nil, guardian.DecisionRequest{}, err
			}
			return guard, guardian.DecisionRequest{
				Principal: "agent-negative-vector",
				Action:    "tool.call",
				Resource:  "tool.with.no.rule",
				Context:   map[string]any{},
			}, nil
		},
	}
}

// unavailablePDP refuses to answer. This is the vector's trigger stated
// literally — not the escape hatch of a stub that returns an arbitrary reason
// code, which would prove nothing about any gate.
type unavailablePDP struct{}

func (unavailablePDP) Evaluate(context.Context, *pdp.DecisionRequest) (*pdp.DecisionResponse, error) {
	return nil, fmt.Errorf("policy decision point is unreachable")
}

func (unavailablePDP) Backend() pdp.Backend { return pdp.Backend("unavailable") }

func (unavailablePDP) PolicyHash() string { return "sha256:" + strings.Repeat("0", 64) }

func casePDPOutage() Case {
	return Case{
		VectorID: "pdp-outage",
		Build: func() (*guardian.Guardian, guardian.DecisionRequest, error) {
			guard, err := newGuardian(prg.NewGraph(), guardian.WithPDP(unavailablePDP{}))
			if err != nil {
				return nil, guardian.DecisionRequest{}, err
			}
			return guard, guardian.DecisionRequest{
				Principal: "agent-negative-vector",
				Action:    "tool.call",
				Resource:  "any.tool",
				Context:   map[string]any{},
			}, nil
		},
	}
}

// caseMissingCredentials asks for a tool call with an identity that carries no
// credential binding.
func caseMissingCredentials() Case {
	return Case{
		VectorID: "missing-credentials",
		Build: func() (*guardian.Guardian, guardian.DecisionRequest, error) {
			guard, err := newGuardian(prg.NewGraph(),
				guardian.WithIsolationChecker(identity.NewIsolationChecker()))
			if err != nil {
				return nil, guardian.DecisionRequest{}, err
			}
			return guard, guardian.DecisionRequest{
				Principal: "agent-negative-vector",
				Action:    "tool.call",
				Resource:  "any.tool",
				// credential_hash deliberately absent.
				Context: map[string]any{"security_context_trusted": true},
			}, nil
		},
	}
}

// caseBlockedEgress attempts egress to a destination outside the declared
// grant. The trusted-context flag matters: destination is a reserved key that
// the gate only reads when a trusted transport bound it, so without the flag
// the egress gate never fires at all.
func caseBlockedEgress() Case {
	return Case{
		VectorID: "blocked-egress",
		Build: func() (*guardian.Guardian, guardian.DecisionRequest, error) {
			policy := &firewall.EgressPolicy{
				AllowedDomains:   []string{"allowed.example.com"},
				AllowedProtocols: []string{"https"},
			}
			guard, err := newGuardian(prg.NewGraph(),
				guardian.WithEgressChecker(firewall.NewEgressChecker(policy)))
			if err != nil {
				return nil, guardian.DecisionRequest{}, err
			}
			return guard, guardian.DecisionRequest{
				Principal: "agent-negative-vector",
				Action:    "network.egress",
				Resource:  "http.client",
				Context: map[string]any{
					"security_context_trusted": true,
					"credential_hash":          "sha256:" + strings.Repeat("1", 64),
					"destination":              "exfiltration.example.net",
				},
			}, nil
		},
	}
}
