package authorityrows

import (
	"errors"
	"math/rand/v2"
	"strings"
	"testing"

	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

// Property tests use fixed seeds so a failure reproduces exactly.
const propertyRuns = 2000

var (
	allEffectTypes = []string{"email.send", "payment.transfer", "calendar.write", "repo.push", "ticket.close"}
	epoch          = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
)

func amount(v int64) *int64 { return &v }

func randomTerms(r *rand.Rand) Terms {
	var types []string
	for _, effectType := range allEffectTypes {
		if r.IntN(2) == 0 {
			types = append(types, effectType)
		}
	}
	if len(types) == 0 {
		types = []string{allEffectTypes[r.IntN(len(allEffectTypes))]}
	}
	t := Terms{EffectTypes: types}
	if r.IntN(3) > 0 {
		t.PerCallLimit = amount(r.Int64N(10_000))
	}
	if r.IntN(3) > 0 {
		t.ApprovalThreshold = amount(r.Int64N(10_000))
	}
	t.ValidFrom = epoch.Add(time.Duration(r.IntN(48)) * time.Hour)
	t.ValidUntil = t.ValidFrom.Add(time.Duration(1+r.IntN(240)) * time.Hour)
	return t
}

// narrowed returns terms within parent, drawn at random.
func narrowed(r *rand.Rand, parent Terms) Terms {
	child := Terms{EffectTypes: []string{parent.EffectTypes[r.IntN(len(parent.EffectTypes))]}}
	for _, effectType := range parent.EffectTypes {
		if r.IntN(2) == 0 {
			child.EffectTypes = append(child.EffectTypes, effectType)
		}
	}
	child.PerCallLimit = lowerOrSet(r, parent.PerCallLimit)
	child.ApprovalThreshold = lowerOrSet(r, parent.ApprovalThreshold)
	// Whole seconds, so the window survives the database's microsecond precision.
	seconds := int64(parent.ValidUntil.Sub(parent.ValidFrom) / time.Second)
	start := r.Int64N(seconds)
	child.ValidFrom = parent.ValidFrom.Add(time.Duration(start) * time.Second)
	child.ValidUntil = child.ValidFrom.Add(time.Duration(1+r.Int64N(seconds-start)) * time.Second)
	return child
}

func lowerOrSet(r *rand.Rand, parent *int64) *int64 {
	if parent == nil {
		if r.IntN(2) == 0 {
			return nil
		}
		return amount(r.Int64N(10_000))
	}
	return amount(r.Int64N(*parent + 1))
}

// widened returns a copy of child that exceeds parent in one term, and the term.
func widened(r *rand.Rand, parent, child Terms) (Terms, string) {
	out := child
	out.EffectTypes = append([]string(nil), child.EffectTypes...)
	for {
		switch r.IntN(5) {
		case 0:
			for _, effectType := range allEffectTypes {
				if !contains(parent.EffectTypes, effectType) {
					out.EffectTypes = append(out.EffectTypes, effectType)
					return out, "effect_types"
				}
			}
		case 1:
			if parent.PerCallLimit != nil {
				if r.IntN(2) == 0 {
					out.PerCallLimit = nil
				} else {
					out.PerCallLimit = amount(*parent.PerCallLimit + 1 + r.Int64N(100))
				}
				return out, "per_call_limit"
			}
		case 2:
			if parent.ApprovalThreshold != nil {
				if r.IntN(2) == 0 {
					out.ApprovalThreshold = nil
				} else {
					out.ApprovalThreshold = amount(*parent.ApprovalThreshold + 1 + r.Int64N(100))
				}
				return out, "approval_threshold"
			}
		case 3:
			out.ValidFrom = parent.ValidFrom.Add(-time.Duration(1+r.IntN(3600)) * time.Second)
			return out, "valid_from"
		case 4:
			out.ValidUntil = parent.ValidUntil.Add(time.Duration(1+r.IntN(3600)) * time.Second)
			return out, "valid_until"
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func mustNormalize(t *testing.T, terms Terms) Terms {
	t.Helper()
	out, err := normalized(terms)
	if err != nil {
		t.Fatalf("normalize %+v: %v", terms, err)
	}
	return out
}

func TestWithinAcceptsEveryNarrowingAndNamesEveryWidening(t *testing.T) {
	r := rand.New(rand.NewPCG(750, 2))
	for run := 0; run < propertyRuns; run++ {
		parent := mustNormalize(t, randomTerms(r))
		child := mustNormalize(t, narrowed(r, parent))
		if err := child.Within(parent); err != nil {
			t.Fatalf("run %d: narrowed terms refused: %v\nparent %+v\nchild  %+v", run, err, parent, child)
		}
		if err := parent.Within(parent); err != nil {
			t.Fatalf("run %d: terms are not within themselves: %v", run, err)
		}
		wide, field := widened(r, parent, child)
		wide = mustNormalize(t, wide)
		err := wide.Within(parent)
		var widens *WidensError
		if !errors.As(err, &widens) || !errors.Is(err, ErrWidens) {
			t.Fatalf("run %d: widening %s accepted: %v\nparent %+v\nwide   %+v", run, field, err, parent, wide)
		}
		if widens.Field != field {
			t.Fatalf("run %d: widening %s reported as %s", run, field, widens.Field)
		}
	}
}

// Within is transitive: a chain built one narrowing at a time is within every
// ancestor, which is what lets admission check each link independently.
func TestWithinIsTransitiveAlongRandomChains(t *testing.T) {
	r := rand.New(rand.NewPCG(750, 3))
	for run := 0; run < propertyRuns/10; run++ {
		chain := []Terms{mustNormalize(t, randomTerms(r))}
		for depth := 0; depth < 8; depth++ {
			chain = append(chain, mustNormalize(t, narrowed(r, chain[len(chain)-1])))
		}
		for i := range chain {
			for j := 0; j <= i; j++ {
				if err := chain[i].Within(chain[j]); err != nil {
					t.Fatalf("run %d: link %d is not within ancestor %d: %v", run, i, j, err)
				}
			}
		}
	}
}

func TestNormalizedRefusesMalformedTerms(t *testing.T) {
	valid := Terms{EffectTypes: []string{"email.send"}, ValidFrom: epoch, ValidUntil: epoch.Add(time.Hour)}
	for name, mutate := range map[string]func(*Terms){
		"no effect types":     func(t *Terms) { t.EffectTypes = nil },
		"bad effect type":     func(t *Terms) { t.EffectTypes = []string{"Email Send"} },
		"negative per call":   func(t *Terms) { t.PerCallLimit = amount(-1) },
		"negative threshold":  func(t *Terms) { t.ApprovalThreshold = amount(-1) },
		"no window":           func(t *Terms) { t.ValidFrom = time.Time{} },
		"empty window":        func(t *Terms) { t.ValidUntil = t.ValidFrom },
		"sub-microsecond gap": func(t *Terms) { t.ValidUntil = t.ValidFrom.Add(time.Nanosecond) },
	} {
		terms := valid
		mutate(&terms)
		if _, err := normalized(terms); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	got := mustNormalize(t, Terms{
		EffectTypes: []string{"repo.push", "email.send", "repo.push"},
		ValidFrom:   epoch.In(time.FixedZone("x", 3600)).Add(1500 * time.Nanosecond),
		ValidUntil:  epoch.Add(time.Hour),
	})
	if len(got.EffectTypes) != 2 || got.EffectTypes[0] != "email.send" || got.EffectTypes[1] != "repo.push" {
		t.Fatalf("effect types not sorted and de-duplicated: %v", got.EffectTypes)
	}
	if got.ValidFrom != epoch.Add(time.Microsecond) || got.ValidFrom.Location() != time.UTC {
		t.Fatalf("valid_from = %v, want UTC at microsecond precision", got.ValidFrom)
	}
}

func TestWideningApprovalMustNameTwoDistinctPrincipals(t *testing.T) {
	for approval, want := range map[WideningApproval]error{
		{}:                       ErrApprovalRequired,
		{RequesterID: "agent-1"}: ErrApprovalRequired,
		{ApproverID: "human-1"}:  ErrApprovalRequired,
		{RequesterID: "human-1", ApproverID: "human-1"}: ErrApproverNotDistinct,
		{RequesterID: "agent-1", ApproverID: "human-1"}: nil,
	} {
		if err := approval.check(); !errors.Is(err, want) {
			t.Errorf("%+v: err = %v, want %v", approval, err, want)
		}
	}
}

func TestLimitSpecValidation(t *testing.T) {
	valid := LimitSpec{Unit: "usd_cents", Measure: "sum", Window: "day", Value: 100, Span: 1}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid limit refused: %v", err)
	}
	for name, mutate := range map[string]func(*LimitSpec){
		"unit":             func(l *LimitSpec) { l.Unit = "USD" },
		"measure":          func(l *LimitSpec) { l.Measure = "avg" },
		"window":           func(l *LimitSpec) { l.Window = "week" },
		"negative":         func(l *LimitSpec) { l.Value = -1 },
		"span zero":        func(l *LimitSpec) { l.Span = 0 },
		"span too long":    func(l *LimitSpec) { l.Span = 745 },
		"sliding none":     func(l *LimitSpec) { l.Window, l.Span = "none", 2 },
		"sliding distinct": func(l *LimitSpec) { l.Measure, l.Span = "distinct", 2 },
	} {
		spec := valid
		mutate(&spec)
		if err := spec.validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestScopeNormalization(t *testing.T) {
	id := "0192A0B4-0000-7000-8000-000000000001"
	got, err := Scope{Kind: ScopeMandate, Key: id}.normalized()
	if err != nil || got.Key != "0192a0b4-0000-7000-8000-000000000001" {
		t.Fatalf("mandate scope = %+v, %v; want the canonical uuid", got, err)
	}
	for _, scope := range []Scope{
		{Kind: ScopeMandate, Key: "not-a-uuid"},
		{Kind: ScopePrincipal, Key: " "},
		{Kind: "workspace", Key: "w"},
	} {
		if _, err := scope.normalized(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: err = %v, want ErrInvalid", scope, err)
		}
	}
}

// HELM-750 s2b terms: targets, a CEL condition and per-effect risk classes.
func TestMandateTermsTargetsRiskAndCondition(t *testing.T) {
	base := Terms{EffectTypes: []string{"repo.push"}, ValidFrom: epoch, ValidUntil: epoch.Add(time.Hour)}
	with := func(edit func(*Terms)) Terms {
		out := base
		edit(&out)
		return out
	}
	outer := with(func(t *Terms) {
		t.Targets = []string{"github.com/o/a", "github.com/o/b"}
		t.RiskClasses = map[string]RiskClass{"repo.push": RiskHigh}
		t.ApprovalRequired = []string{"repo.push"}
	})

	for _, test := range []struct {
		name  string
		inner Terms
		field string // "" when inner is within outer
	}{
		{"subset of targets, same risk", with(func(t *Terms) {
			t.Targets = []string{"github.com/o/a"}
			t.RiskClasses = map[string]RiskClass{"repo.push": RiskHigh}
			t.ApprovalRequired = []string{"repo.push"}
		}), ""},
		{"raised risk", with(func(t *Terms) {
			t.Targets = []string{"github.com/o/a"}
			t.RiskClasses = map[string]RiskClass{"repo.push": RiskIrreversible}
			t.ApprovalRequired = []string{"repo.push"}
		}), ""},
		{"a condition of its own", with(func(t *Terms) {
			t.Targets = []string{"github.com/o/a"}
			t.RiskClasses = map[string]RiskClass{"repo.push": RiskHigh}
			t.Condition = `input.args.head.startsWith("helm/")`
			t.ApprovalRequired = []string{"repo.push"}
		}), ""},
		{"no target list under one", with(func(t *Terms) {
			t.RiskClasses = map[string]RiskClass{"repo.push": RiskHigh}
		}), "targets"},
		{"a target outside the list", with(func(t *Terms) {
			t.Targets = []string{"github.com/o/c"}
			t.RiskClasses = map[string]RiskClass{"repo.push": RiskHigh}
		}), "targets"},
		{"lowered risk", with(func(t *Terms) {
			t.Targets = []string{"github.com/o/a"}
			t.RiskClasses = map[string]RiskClass{"repo.push": RiskMedium}
		}), "risk_classes"},
		{"dropped risk", with(func(t *Terms) { t.Targets = []string{"github.com/o/a"} }), "risk_classes"},
		{"dropped approval requirement", with(func(t *Terms) {
			t.Targets = []string{"github.com/o/a"}
			t.RiskClasses = map[string]RiskClass{"repo.push": RiskHigh}
			t.ApprovalRequired = nil
		}), "approval_required"},
	} {
		err := test.inner.Within(outer)
		var widens *WidensError
		switch {
		case test.field == "" && err != nil:
			t.Fatalf("%s: %v", test.name, err)
		case test.field != "" && (!errors.As(err, &widens) || widens.Field != test.field):
			t.Fatalf("%s: err = %v, want widening of %s", test.name, err, test.field)
		}
	}

	for _, refused := range []struct {
		name  string
		terms Terms
	}{
		{"empty target list", with(func(t *Terms) { t.Targets = []string{} })},
		{"control character in a target", with(func(t *Terms) { t.Targets = []string{"github.com/o/a\n"} })},
		{"condition that does not compile", with(func(t *Terms) { t.Condition = "input.args.head.startsWith(" })},
		{"condition over the limit", with(func(t *Terms) { t.Condition = strings.Repeat("a", MaxConditionBytes+1) })},
		{"risk class for an effect type out of scope", with(func(t *Terms) { t.RiskClasses = map[string]RiskClass{"email.send": RiskHigh} })},
		{"unknown risk class", with(func(t *Terms) { t.RiskClasses = map[string]RiskClass{"repo.push": "severe"} })},
		{"approval required for an effect type out of scope", with(func(t *Terms) { t.ApprovalRequired = []string{"email.send"} })},
	} {
		if _, err := normalized(refused.terms); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: err = %v, want ErrInvalid", refused.name, err)
		}
	}
	got, err := normalized(with(func(t *Terms) { t.Targets = []string{"b", "a", "b"} }))
	if err != nil || strings.Join(got.Targets, ",") != "a,b" {
		t.Fatalf("targets normalize to %v, %v; want sorted and de-duplicated", got.Targets, err)
	}
	if mandates.HigherRisk(RiskMedium, RiskHigh) != RiskHigh || mandates.HigherRisk(RiskIrreversible, "") != RiskIrreversible {
		t.Fatal("HigherRisk does not order risk classes")
	}
}
