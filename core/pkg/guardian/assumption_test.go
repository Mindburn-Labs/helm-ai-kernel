package guardian

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

func assumptionGuardian(t *testing.T, opts ...GuardianOption) *Guardian {
	t.Helper()
	signer, err := crypto.NewEd25519SignerFromSeed([]byte("assumption-freshness-gate-seed!!"), "assumption-test")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return NewGuardian(signer, prg.NewGraph(), nil, opts...)
}

func freshAssumption() contracts.ObservedAssumption {
	return contracts.ObservedAssumption{
		AssumptionID:    "issue-open",
		Subject:         "github://Mindburn-Labs/helm-ai-kernel/issues/1",
		ObservationType: "api_response",
		ContentHash:     "sha256:" + strings.Repeat("a", 64),
		CapturedAt:      time.Now().Add(-time.Minute),
		TTLSeconds:      3600,
	}
}

func requestWith(assumption contracts.ObservedAssumption) DecisionRequest {
	return DecisionRequest{
		Principal: "agent-assumption",
		Action:    "tool.call",
		Resource:  "github.close_issue",
		Context: map[string]any{
			"plan_hash":        "sha256:" + strings.Repeat("b", 64),
			ContextAssumptions: []contracts.ObservedAssumption{assumption},
		},
	}
}

// The gap this closes: ERR_ASSUMPTION_STALE was declared in the reason-code
// registry and given a conformance vector, with no producer anywhere.
func TestExpiredAssumptionDeniesWithAssumptionStale(t *testing.T) {
	guard := assumptionGuardian(t)

	stale := freshAssumption()
	stale.CapturedAt = time.Now().Add(-2 * time.Hour)
	stale.TTLSeconds = 60

	decision, err := guard.EvaluateDecision(context.Background(), requestWith(stale))
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	if decision.Verdict != string(contracts.VerdictDeny) {
		t.Errorf("verdict = %q, want DENY", decision.Verdict)
	}
	if decision.ReasonCode != string(contracts.ReasonAssumptionStale) {
		t.Fatalf("reason code = %q, want %q", decision.ReasonCode, contracts.ReasonAssumptionStale)
	}

	// The conformance vector requires plan_hash and assumption_hash bound as
	// evidence; InputContext is covered by the decision signature.
	for _, key := range []string{"plan_hash", "assumption_hash"} {
		value, ok := decision.InputContext[key].(string)
		if !ok || value == "" {
			t.Errorf("denial does not bind %q as evidence", key)
		}
	}
	if decision.Signature == "" {
		t.Error("denial is unsigned and cannot be verified offline")
	}

	// MustNotDispatch: a refused decision must not yield execution authority.
	effect := &contracts.Effect{EffectID: "eff-stale", EffectType: "tool.call"}
	if _, err := guard.IssueExecutionIntent(context.Background(), decision, effect); err == nil {
		t.Error("execution intent was issued for a refused decision")
	}
}

func TestFreshAssumptionDoesNotDeny(t *testing.T) {
	guard := assumptionGuardian(t)

	decision, err := guard.EvaluateDecision(context.Background(), requestWith(freshAssumption()))
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	if decision.ReasonCode == string(contracts.ReasonAssumptionStale) {
		t.Error("a fresh assumption was reported stale")
	}
}

// An action that declares nothing is untouched: deciding when an assumption is
// required is a policy question, not this gate's.
func TestNoAssumptionsPassesThrough(t *testing.T) {
	guard := assumptionGuardian(t)

	decision, err := guard.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-assumption",
		Action:    "tool.call",
		Resource:  "github.read_issue",
		Context:   map[string]any{},
	})
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	if decision.ReasonCode == string(contracts.ReasonAssumptionStale) {
		t.Error("an action declaring no assumptions was denied as stale")
	}
}

type observer struct {
	hash string
	err  error
}

func (o observer) Observe(context.Context, contracts.ObservedAssumption) (string, error) {
	return o.hash, o.err
}

func TestObservedDriftWithinTTLDenies(t *testing.T) {
	guard := assumptionGuardian(t, WithAssumptionObserver(observer{hash: "sha256:" + strings.Repeat("c", 64)}))

	decision, err := guard.EvaluateDecision(context.Background(), requestWith(freshAssumption()))
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	if decision.ReasonCode != string(contracts.ReasonAssumptionStale) {
		t.Errorf("reason code = %q, want %q — the world moved inside the validity window",
			decision.ReasonCode, contracts.ReasonAssumptionStale)
	}
}

// A gate that cannot check cannot vouch.
func TestUnreachableObserverDenies(t *testing.T) {
	guard := assumptionGuardian(t, WithAssumptionObserver(observer{err: fmt.Errorf("target unreachable")}))

	decision, err := guard.EvaluateDecision(context.Background(), requestWith(freshAssumption()))
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	if decision.ReasonCode != string(contracts.ReasonAssumptionStale) {
		t.Errorf("reason code = %q, want %q — an unconfirmable assumption must fail closed",
			decision.ReasonCode, contracts.ReasonAssumptionStale)
	}
}

func TestMalformedAssumptionDenies(t *testing.T) {
	guard := assumptionGuardian(t)

	broken := freshAssumption()
	broken.ContentHash = "not-a-digest"

	decision, err := guard.EvaluateDecision(context.Background(), requestWith(broken))
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	if decision.ReasonCode != string(contracts.ReasonAssumptionStale) {
		t.Errorf("reason code = %q, want %q", decision.ReasonCode, contracts.ReasonAssumptionStale)
	}
}

func TestSealIsDeterministicAndCoversContent(t *testing.T) {
	// Fixed capture time: the seal covers CapturedAt, so two observations
	// taken at different instants are correctly different assumptions.
	at := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	pinned := func() contracts.ObservedAssumption {
		a := freshAssumption()
		a.CapturedAt = at
		return a
	}

	first := pinned()
	if err := first.Seal(); err != nil {
		t.Fatalf("sealing: %v", err)
	}
	second := pinned()
	if err := second.Seal(); err != nil {
		t.Fatalf("sealing: %v", err)
	}
	if first.AssumptionHash != second.AssumptionHash {
		t.Errorf("seal is not deterministic: %q vs %q", first.AssumptionHash, second.AssumptionHash)
	}

	moved := pinned()
	moved.ContentHash = "sha256:" + strings.Repeat("d", 64)
	if err := moved.Seal(); err != nil {
		t.Fatalf("sealing: %v", err)
	}
	if moved.AssumptionHash == first.AssumptionHash {
		t.Error("seal did not change when the observed content changed")
	}
}

// A zero TTL means no validity window was declared, which is not the same as
// an unlimited one.
func TestZeroTTLIsExpiredImmediately(t *testing.T) {
	a := freshAssumption()
	a.CapturedAt = time.Now()
	a.TTLSeconds = 0
	if !a.Expired(time.Now()) {
		t.Error("an assumption with no validity window was treated as fresh")
	}
}
