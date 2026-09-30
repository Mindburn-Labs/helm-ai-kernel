package admission

// quantum_posture: checks SHA-256 test vectors; signs nothing.

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

// The approval digest v1 vector of docs/architecture/gateway-effect-api.md.
func TestApprovalDigestV1MatchesTheDesignNoteVector(t *testing.T) {
	target := sha256.Sum256([]byte("github.com/Mindburn-Labs/example/pull/42"))
	args := sha256.Sum256([]byte(`{"merge_method":"squash"}`))
	quote := []Amount{{Unit: "count", Amount: 1}, {Unit: "USD", Amount: 2500}}
	const id = "0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d"
	const want = "7efd7515c4c739e32f6c61ef3214bff08013771f5fdc02da1dd2b1e3806edf31"
	whole := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	if got := hex.EncodeToString(ApprovalDigestV1(id, target[:], args[:], quote, whole)); got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}
	// A fraction of a second is truncated, whatever the zone.
	fraction := time.Date(2026, 9, 26, 15, 0, 0, 987654000, time.FixedZone("EEST", 3*3600))
	if got := hex.EncodeToString(ApprovalDigestV1(id, target[:], args[:], quote, fraction)); got != want {
		t.Fatalf("sub-second digest = %s, want %s", got, want)
	}
	// Known bad: another second, another quote order is the same, another amount is not.
	if got := hex.EncodeToString(ApprovalDigestV1(id, target[:], args[:], quote, whole.Add(time.Second))); got == want {
		t.Fatal("a different expires_at gives the same digest")
	}
	reordered := []Amount{quote[1], quote[0]}
	if got := hex.EncodeToString(ApprovalDigestV1(id, target[:], args[:], reordered, whole)); got != want {
		t.Fatal("the quote's order changes the digest")
	}
	if got := hex.EncodeToString(ApprovalDigestV1(id, target[:], args[:], []Amount{{"count", 2}, {"USD", 2500}}, whole)); got == want {
		t.Fatal("a different amount gives the same digest")
	}
}

func TestRequestDigestCoversEveryFieldButTheKey(t *testing.T) {
	caller := Caller{TenantID: "t", WorkspaceID: "w", PrincipalID: "p"}
	expires := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	base := ProposeInput{IdempotencyKey: "k", MandateID: "m", CommitmentID: "c", EffectType: "e", Target: "x",
		Arguments: []byte("{}"), Quote: []Amount{{"a", 1}, {"b", 2}}, Distinct: []DistinctValue{{"u", make([]byte, 32)}},
		ApprovalExpiresAt: &expires}
	digest := string(requestDigest(caller, base))

	same := base
	same.IdempotencyKey = "other"
	same.Quote = []Amount{{"b", 2}, {"a", 1}}
	fraction := expires.Add(500 * time.Millisecond)
	same.ApprovalExpiresAt = &fraction
	if string(requestDigest(caller, same)) != digest {
		t.Fatal("the key, the quote order or a sub-second change altered the request digest")
	}
	later := expires.Add(time.Second)
	for name, edit := range map[string]func(*ProposeInput, *Caller){
		"mandate":     func(in *ProposeInput, _ *Caller) { in.MandateID = "m2" },
		"work ref":    func(in *ProposeInput, _ *Caller) { in.CommitmentID, in.CaseID = "", "c" },
		"effect type": func(in *ProposeInput, _ *Caller) { in.EffectType = "e2" },
		"target":      func(in *ProposeInput, _ *Caller) { in.Target = "y" },
		"arguments":   func(in *ProposeInput, _ *Caller) { in.Arguments = []byte(`{"a":1}`) },
		"quote":       func(in *ProposeInput, _ *Caller) { in.Quote = []Amount{{"a", 1}} },
		"distinct":    func(in *ProposeInput, _ *Caller) { in.Distinct = nil },
		"expiry":      func(in *ProposeInput, _ *Caller) { in.ApprovalExpiresAt = &later },
		"principal":   func(_ *ProposeInput, c *Caller) { c.PrincipalID = "p2" },
		"workspace":   func(_ *ProposeInput, c *Caller) { c.WorkspaceID = "w2" },
	} {
		in, c := base, caller
		edit(&in, &c)
		if string(requestDigest(c, in)) == digest {
			t.Fatalf("changing the %s does not change the request digest", name)
		}
	}
}

// decideBase is an input that allows: one active root mandate, a low-risk
// effect type, no stops, no counters.
func decideBase(t *testing.T) Input {
	t.Helper()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	return Input{
		Now: now, PrincipalID: "human-a", PrincipalFound: true, PrincipalActive: true,
		EffectType: "github.branch.create_from_changes", EffectTypeFound: true, RiskClass: mandates.RiskMedium,
		Target: "github.com/o/r", Args: map[string]any{"head": "helm/x"},
		Chain: []Link{{Mandate: mandates.Mandate{ID: uuid.New(), HolderID: "human-a", Active: true, Terms: mandates.Terms{
			EffectTypes: []string{"github.branch.create_from_changes"}, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
		}}}},
	}
}

func withCondition(t *testing.T, in Input, condition string) Input {
	t.Helper()
	snapshot, err := mandates.CompileCondition(condition)
	if err != nil {
		t.Fatal(err)
	}
	in.Chain[len(in.Chain)-1].Mandate.Terms.Condition = condition
	in.Chain[len(in.Chain)-1].Condition = snapshot
	return in
}

func amountPtr(v int64) *int64 { return &v }

func TestDecideAllowsDeniesAndEscalatesInOrder(t *testing.T) {
	type edit func(*testing.T, Input) Input
	root := func(f func(*mandates.Terms)) edit {
		return func(_ *testing.T, in Input) Input { f(&in.Chain[0].Mandate.Terms); return in }
	}
	for _, test := range []struct {
		name    string
		edit    edit
		verdict Verdict
		reason  contracts.ReasonCode
	}{
		{"allowed", func(_ *testing.T, in Input) Input { return in }, Allow, ""},
		{"a stop wins over everything", func(_ *testing.T, in Input) Input {
			in.ActiveStops, in.PrincipalActive = []string{"s"}, false
			return in
		}, Deny, contracts.ReasonEmergencyStopFenced},
		{"unknown principal", func(_ *testing.T, in Input) Input { in.PrincipalFound = false; return in }, Deny, contracts.ReasonPrincipalInactive},
		{"disabled principal", func(_ *testing.T, in Input) Input { in.PrincipalActive = false; return in }, Deny, contracts.ReasonPrincipalInactive},
		{"no mandate", func(_ *testing.T, in Input) Input { in.Chain = nil; return in }, Deny, contracts.ReasonMandateInactive},
		{"revoked mandate", func(_ *testing.T, in Input) Input { in.Chain[0].Mandate.Active = false; return in }, Deny, contracts.ReasonMandateInactive},
		{"expired mandate", root(func(m *mandates.Terms) { m.ValidUntil = m.ValidFrom.Add(time.Minute) }), Deny, contracts.ReasonMandateOutsideValidity},
		{"effect type out of scope", root(func(m *mandates.Terms) { m.EffectTypes = []string{"other"} }), Deny, contracts.ReasonEffectOutOfScope},
		{"target not allowlisted", root(func(m *mandates.Terms) { m.Targets = []string{"github.com/o/other"} }), Deny, contracts.ReasonEffectOutOfScope},
		{"target allowlisted", root(func(m *mandates.Terms) { m.Targets = []string{"github.com/o/r"} }), Allow, ""},
		{"per-call limit", func(_ *testing.T, in Input) Input {
			in.Chain[0].Mandate.Terms.PerCallLimit = amountPtr(10)
			in.Quote = []Amount{{"usd_cents", 11}}
			return in
		}, Deny, contracts.ReasonPerCallLimit},
		{"quote overflow", func(_ *testing.T, in Input) Input {
			in.Quote = []Amount{{"a", math.MaxInt64}, {"b", 1}}
			return in
		}, Deny, contracts.ReasonArithmeticOverflow},
		{"condition holds", func(t *testing.T, in Input) Input {
			return withCondition(t, in, `input.args.head.startsWith("helm/")`)
		}, Allow, ""},
		{"condition fails: head on the default branch", func(t *testing.T, in Input) Input {
			in.Args = map[string]any{"head": "main"}
			return withCondition(t, in, `input.args.head.startsWith("helm/")`)
		}, Deny, contracts.ReasonMissingRequirement},
		{"condition on a missing field", func(t *testing.T, in Input) Input {
			in.Args = map[string]any{}
			return withCondition(t, in, `input.args.head.startsWith("helm/")`)
		}, Deny, contracts.ReasonPRGEvalError},
		{"condition that did not compile", func(_ *testing.T, in Input) Input {
			in.Chain[0].Mandate.Terms.Condition = "input.args.head.startsWith("
			return in
		}, Deny, contracts.ReasonPRGEvalError},
		{"effect type without a control row", func(_ *testing.T, in Input) Input { in.EffectTypeFound = false; return in }, Deny, contracts.ReasonEffectOutOfScope},
		{"counter full", func(_ *testing.T, in Input) Input {
			in.Counters = []CounterState{{LimitID: "l", Limit: 5, Used: 3, Reserved: 2, Delta: 1}}
			return in
		}, Deny, contracts.ReasonBudgetExceeded},
		{"counter overflow", func(_ *testing.T, in Input) Input {
			in.Counters = []CounterState{{LimitID: "l", Limit: math.MaxInt64, Used: math.MaxInt64, Delta: 1}}
			return in
		}, Deny, contracts.ReasonArithmeticOverflow},
		{"counter with room", func(_ *testing.T, in Input) Input {
			in.Counters = []CounterState{{LimitID: "l", Limit: 5, Used: 3, Reserved: 1, Delta: 1}}
			return in
		}, Allow, ""},
		{"high risk escalates", func(_ *testing.T, in Input) Input { in.RiskClass = mandates.RiskHigh; return in }, Escalate, contracts.ReasonApprovalRequired},
		{"irreversible escalates", func(_ *testing.T, in Input) Input { in.RiskClass = mandates.RiskIrreversible; return in }, Escalate, contracts.ReasonApprovalRequired},
		{"approval threshold escalates", root(func(m *mandates.Terms) { m.ApprovalThreshold = amountPtr(0) }), Escalate, contracts.ReasonApprovalRequired},
		{"a mandate requires approval for a medium effect", root(func(m *mandates.Terms) {
			m.ApprovalRequired = []string{"github.branch.create_from_changes"}
		}), Escalate, contracts.ReasonApprovalRequired},
		{"approval required for another effect type", root(func(m *mandates.Terms) {
			m.ApprovalRequired = []string{"github.pull_request.create_draft"}
		}), Allow, ""},
		{"approved by a distinct human", func(_ *testing.T, in Input) Input {
			in.RiskClass = mandates.RiskHigh
			in.Approval = &ApprovalState{ApproverID: "human-b", Approved: true}
			return in
		}, Allow, ""},
		{"approved by the requester (backstop)", func(_ *testing.T, in Input) Input {
			in.RiskClass = mandates.RiskHigh
			in.Approval = &ApprovalState{ApproverID: "human-a", Approved: true}
			return in
		}, Deny, contracts.ReasonApproverNotDistinct},
		{"rejected", func(_ *testing.T, in Input) Input {
			in.RiskClass = mandates.RiskHigh
			in.Approval = &ApprovalState{ApproverID: "human-b"}
			return in
		}, Deny, contracts.ReasonApprovalRejected},
		{"a stop after the approval", func(_ *testing.T, in Input) Input {
			in.RiskClass = mandates.RiskHigh
			in.Approval = &ApprovalState{ApproverID: "human-b", Approved: true}
			in.ActiveStops = []string{"s"}
			return in
		}, Deny, contracts.ReasonEmergencyStopFenced},
		{"a denial beats escalation", func(_ *testing.T, in Input) Input {
			in.RiskClass = mandates.RiskHigh
			in.Counters = []CounterState{{LimitID: "l", Limit: 0, Delta: 1}}
			return in
		}, Deny, contracts.ReasonBudgetExceeded},
		{"a delegated link wider than its parent", func(_ *testing.T, in Input) Input {
			child := in.Chain[0]
			child.Mandate.ID = uuid.New()
			child.Mandate.Terms.ValidUntil = child.Mandate.Terms.ValidUntil.Add(time.Hour)
			in.Chain = append(in.Chain, child)
			return in
		}, Deny, contracts.ReasonDelegationScopeViolation},
		{"a delegated link that narrows", func(_ *testing.T, in Input) Input {
			child := in.Chain[0]
			child.Mandate.ID = uuid.New()
			child.Mandate.Terms.ValidUntil = child.Mandate.Terms.ValidUntil.Add(-time.Minute)
			in.Chain = append(in.Chain, child)
			return in
		}, Allow, ""},
	} {
		got := Decide(test.edit(t, decideBase(t)))
		if got.Verdict != test.verdict || got.Reason != test.reason {
			t.Errorf("%s: Decide = %s %s, want %s %s", test.name, got.Verdict, got.Reason, test.verdict, test.reason)
		}
	}
}

func TestStepUpCoversHighIrreversibleAndAuthorityChanges(t *testing.T) {
	for _, test := range []struct {
		risk, effectType string
		want             bool
	}{
		{"high", "github.pull_request.merge", true},
		{"irreversible", "payment.send", true},
		{"low", "helm.authority.lift", true},
		{"medium", "github.pull_request.create_draft", false},
		{"low", "github.repository.get", false},
	} {
		if got := needsStepUp(test.risk, test.effectType); got != test.want {
			t.Errorf("%s %s: needsStepUp = %v, want %v", test.risk, test.effectType, got, test.want)
		}
	}
}
