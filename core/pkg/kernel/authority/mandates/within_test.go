package mandates

// CTL-046: Terms.Within is the one narrowing rule. The authority store applies
// it when it delegates, narrows or limits a mandate, the gateway's provisioning
// compile applies it to every node of a plan, and admission re-applies it to
// every link of a chain. These cases name each term it compares, one at a
// time, so that deleting any one comparison fails here and no other term can
// stand in for it.

import (
	"errors"
	"testing"
	"time"
)

var windowStart = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

func units(v int64) *int64 { return &v }

// ceilingTerms sets every term Within compares, so a widening of any one of
// them is a widening of something the ceiling set.
func ceilingTerms() Terms {
	return Terms{
		EffectTypes:       []string{"email.send", "repo.push"},
		PerCallLimit:      units(100),
		ApprovalThreshold: units(50),
		ValidFrom:         windowStart,
		ValidUntil:        windowStart.Add(10 * time.Hour),
		Targets:           []string{"github.com/o/a", "github.com/o/b"},
		ApprovalRequired:  []string{"repo.push"},
		RiskClasses:       map[string]RiskClass{"repo.push": RiskHigh},
	}
}

func TestWithinNamesEachWideningDimension(t *testing.T) {
	for _, test := range []struct {
		name  string
		edit  func(*Terms)
		field string // "" when the edited terms are within the ceiling
	}{
		// Terms that grant nothing the ceiling does not.
		{"the same terms", func(*Terms) {}, ""},
		{"fewer effect types", func(t *Terms) { t.EffectTypes = []string{"repo.push"} }, ""},
		{"a per-call limit at the ceiling", func(t *Terms) { t.PerCallLimit = units(100) }, ""},
		{"a lower per-call limit", func(t *Terms) { t.PerCallLimit = units(99) }, ""},
		{"a lower approval threshold, which asks for approval on more calls", func(t *Terms) { t.ApprovalThreshold = units(49) }, ""},
		{"a window inside", func(t *Terms) {
			t.ValidFrom, t.ValidUntil = windowStart.Add(time.Second), windowStart.Add(10*time.Hour-time.Second)
		}, ""},
		{"a subset of the targets", func(t *Terms) { t.Targets = []string{"github.com/o/a"} }, ""},
		{"a raised risk class", func(t *Terms) { t.RiskClasses = map[string]RiskClass{"repo.push": RiskIrreversible} }, ""},
		{"more approval requirements", func(t *Terms) { t.ApprovalRequired = []string{"email.send", "repo.push"} }, ""},

		// One term wider, every other term as before.
		{"an extra effect type", func(t *Terms) { t.EffectTypes = []string{"email.send", "payment.transfer", "repo.push"} }, "effect_types"},
		{"a per-call limit one above", func(t *Terms) { t.PerCallLimit = units(101) }, "per_call_limit"},
		{"no per-call limit", func(t *Terms) { t.PerCallLimit = nil }, "per_call_limit"},
		{"an approval threshold one above", func(t *Terms) { t.ApprovalThreshold = units(51) }, "approval_threshold"},
		{"no approval threshold", func(t *Terms) { t.ApprovalThreshold = nil }, "approval_threshold"},
		{"a window that opens a second early", func(t *Terms) { t.ValidFrom = windowStart.Add(-time.Second) }, "valid_from"},
		{"a window that closes a second late", func(t *Terms) { t.ValidUntil = windowStart.Add(10*time.Hour + time.Second) }, "valid_until"},
		{"any target", func(t *Terms) { t.Targets = nil }, "targets"},
		{"a target off the list", func(t *Terms) { t.Targets = []string{"github.com/o/a", "github.com/o/c"} }, "targets"},
		{"a lowered risk class", func(t *Terms) { t.RiskClasses = map[string]RiskClass{"repo.push": RiskMedium} }, "risk_classes"},
		{"a dropped risk class", func(t *Terms) { t.RiskClasses = nil }, "risk_classes"},
		{"a dropped approval requirement", func(t *Terms) { t.ApprovalRequired = nil }, "approval_required"},

		// A narrowing in one term never pays for a widening in another.
		{"a wider window with a lower limit", func(t *Terms) {
			t.PerCallLimit, t.ValidUntil = units(1), windowStart.Add(11*time.Hour)
		}, "valid_until"},
		{"an extra effect type with fewer targets", func(t *Terms) {
			t.EffectTypes, t.Targets = []string{"email.send", "payment.transfer", "repo.push"}, []string{"github.com/o/a"}
		}, "effect_types"},
	} {
		terms := ceilingTerms()
		test.edit(&terms)
		err := terms.Within(ceilingTerms())
		if test.field == "" {
			if err != nil {
				t.Errorf("%s: refused: %v", test.name, err)
			}
			continue
		}
		var widens *WidensError
		if !errors.As(err, &widens) || !errors.Is(err, ErrWidens) || widens.Field != test.field {
			t.Errorf("%s: err = %v, want a widening of %s", test.name, err, test.field)
		}
	}
}

// A ceiling that sets no limit, no target list and no requirement leaves every
// such term to the child: a bound is never read into a ceiling that has none.
func TestWithinAcceptsAnyBoundUnderACeilingThatSetsNone(t *testing.T) {
	open := Terms{EffectTypes: []string{"email.send"}, ValidFrom: windowStart, ValidUntil: windowStart.Add(time.Hour)}
	bounded := open
	bounded.PerCallLimit, bounded.ApprovalThreshold = units(7), units(0)
	bounded.Targets = []string{"github.com/o/a"}
	bounded.RiskClasses = map[string]RiskClass{"email.send": RiskMedium}
	bounded.ApprovalRequired = []string{"email.send"}
	if err := bounded.Within(open); err != nil {
		t.Fatalf("bounded terms under an open ceiling: %v", err)
	}
	if err := open.Within(bounded); err == nil {
		t.Fatal("open terms under a bounded ceiling were accepted")
	}
}
