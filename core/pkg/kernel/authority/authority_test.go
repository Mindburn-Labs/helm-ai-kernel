package authority

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

var testTime = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

func expr(id, expression string) prg.Requirement {
	return prg.Requirement{ID: id, Expression: expression}
}

func compileOne(t *testing.T, set prg.RequirementSet) (*Snapshot, error) {
	t.Helper()
	g := prg.NewGraph()
	require.NoError(t, g.AddRule("act", set))
	return Compile(g)
}

// decideSet compiles a one-rule snapshot, requires it to compile, and decides
// action "act" against attrs.
func decideSet(t *testing.T, set prg.RequirementSet, attrs map[string]any) Decision {
	t.Helper()
	s, err := compileOne(t, set)
	require.NoError(t, err)
	return Decide(Input{Action: "act", Attributes: attrs, Time: testTime}, s)
}

func requireAllow(t *testing.T, d Decision) {
	t.Helper()
	require.Equal(t, contracts.VerdictAllow, d.Verdict, "decision: %+v", d)
	require.Empty(t, d.ReasonCode)
}

func requireDeny(t *testing.T, d Decision, code contracts.ReasonCode) {
	t.Helper()
	require.Equal(t, contracts.VerdictDeny, d.Verdict, "decision: %+v", d)
	require.Equal(t, code, d.ReasonCode, "decision: %+v", d)
}

func TestDecideConditions(t *testing.T) {
	attrs := map[string]any{"user": "admin", "count": 5, "flag": true}
	cases := []struct {
		expression string
		allow      bool
	}{
		{"true", true},
		{"false", false},
		{"1 == 1", true},
		{"1 == 2", false},
		{`input.user == "admin"`, true},
		{`input.user == "guest"`, false},
		{"input.count > 3", true},
		{"input.count > 7", false},
		{"input.flag", true},
		{`"abc" == "abc"`, true},
		{`"abc" == "xyz"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.expression, func(t *testing.T) {
			d := decideSet(t, prg.RequirementSet{ID: "rs", Requirements: []prg.Requirement{expr("r", tc.expression)}}, attrs)
			if tc.allow {
				requireAllow(t, d)
				return
			}
			requireDeny(t, d, contracts.ReasonMissingRequirement)
			require.Equal(t, []string{"r"}, d.Unmet)
		})
	}
}

func TestDecideLogic(t *testing.T) {
	yes, no := expr("yes", "true"), expr("no", "false")
	cases := []struct {
		name  string
		set   prg.RequirementSet
		allow bool
		unmet []string
	}{
		{"empty set allows", prg.RequirementSet{ID: "empty"}, true, nil},
		{"AND all true", prg.RequirementSet{ID: "s", Logic: prg.AND, Requirements: []prg.Requirement{yes, expr("yes2", "1 < 2")}}, true, nil},
		{"AND one false", prg.RequirementSet{ID: "s", Logic: prg.AND, Requirements: []prg.Requirement{yes, no}}, false, []string{"no"}},
		{"default logic is AND", prg.RequirementSet{ID: "s", Requirements: []prg.Requirement{yes, no}}, false, []string{"no"}},
		{"OR one true", prg.RequirementSet{ID: "s", Logic: prg.OR, Requirements: []prg.Requirement{no, yes}}, true, nil},
		{"OR all false", prg.RequirementSet{ID: "s", Logic: prg.OR, Requirements: []prg.Requirement{no, expr("no2", "1 > 2")}}, false, []string{"no", "no2"}},
		{"NOT inverts true", prg.RequirementSet{ID: "not", Logic: prg.NOT, Requirements: []prg.Requirement{yes}}, false, []string{"not"}},
		{"NOT inverts false", prg.RequirementSet{ID: "not", Logic: prg.NOT, Requirements: []prg.Requirement{no}}, true, nil},
		{"NOT of all true is false", prg.RequirementSet{ID: "not", Logic: prg.NOT, Requirements: []prg.Requirement{yes, expr("yes2", "true")}}, false, []string{"not"}},
		{"NOT of mixed is true", prg.RequirementSet{ID: "not", Logic: prg.NOT, Requirements: []prg.Requirement{yes, no}}, true, nil},
		{"nested OR child satisfies AND", prg.RequirementSet{ID: "p", Logic: prg.AND, Requirements: []prg.Requirement{yes},
			Children: []prg.RequirementSet{{ID: "c", Logic: prg.OR, Requirements: []prg.Requirement{no, expr("yes2", "true")}}}}, true, nil},
		{"nested AND child fails", prg.RequirementSet{ID: "p", Logic: prg.AND, Requirements: []prg.Requirement{yes},
			Children: []prg.RequirementSet{{ID: "c", Logic: prg.AND, Requirements: []prg.Requirement{expr("inner", "false")}}}}, false, []string{"inner"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := decideSet(t, tc.set, nil)
			if tc.allow {
				requireAllow(t, d)
				return
			}
			requireDeny(t, d, contracts.ReasonMissingRequirement)
			require.Equal(t, tc.unmet, d.Unmet)
		})
	}
}

func TestDecideUnmetNamesRequirementsNotPolicySource(t *testing.T) {
	d := decideSet(t, prg.RequirementSet{ID: "s", Requirements: []prg.Requirement{
		expr("check-budget", `input.effect.params.budget_id == "secret-policy-tier"`),
	}}, map[string]any{"effect": map[string]any{"params": map[string]any{"budget_id": "other"}}})
	requireDeny(t, d, contracts.ReasonMissingRequirement)
	require.Equal(t, []string{"check-budget"}, d.Unmet)
	require.NotContains(t, fmt.Sprintf("%+v", d), "secret-policy-tier")
}

func TestDecideTaintHelper(t *testing.T) {
	set := prg.RequirementSet{ID: "s", Requirements: []prg.Requirement{expr("no-pii", `!taint_contains("pii")`)}}
	requireAllow(t, decideSet(t, set, map[string]any{"taint": []string{"internal"}}))
	d := decideSet(t, set, map[string]any{"taint": []string{"pii"}})
	requireDeny(t, d, contracts.ReasonMissingRequirement)
}

func TestDecideArtifactRequirement(t *testing.T) {
	set := prg.RequirementSet{ID: "s", Requirements: []prg.Requirement{{ID: "approval", ArtifactType: "human_approval"}}}
	cases := []struct {
		name  string
		attrs map[string]any
		allow bool
	}{
		{"present", map[string]any{"artifacts": []map[string]any{{"type": "human_approval"}}}, true},
		{"other type", map[string]any{"artifacts": []map[string]any{{"type": "alert"}}}, false},
		{"empty list", map[string]any{"artifacts": []any{}}, false},
		{"absent", nil, false},
		{"wrong shape", map[string]any{"artifacts": "human_approval"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := decideSet(t, set, tc.attrs)
			if tc.allow {
				requireAllow(t, d)
				return
			}
			requireDeny(t, d, contracts.ReasonMissingRequirement)
		})
	}
}

// Every way a rule can fail to produce a boolean true is a DENY.
func TestDecideFailsClosed(t *testing.T) {
	t.Run("missing attribute", func(t *testing.T) {
		d := decideSet(t, prg.RequirementSet{ID: "s", Requirements: []prg.Requirement{expr("r", `input.absent == "x"`)}}, nil)
		requireDeny(t, d, contracts.ReasonPRGEvalError)
		require.Contains(t, d.Detail, "no such key")
	})
	t.Run("non-boolean result", func(t *testing.T) {
		d := decideSet(t, prg.RequirementSet{ID: "s", Requirements: []prg.Requirement{expr("r", `"yes"`)}}, nil)
		requireDeny(t, d, contracts.ReasonPRGEvalError)
		require.Contains(t, d.Detail, "not bool")
	})
	t.Run("an error denies even when another leaf allows", func(t *testing.T) {
		d := decideSet(t, prg.RequirementSet{ID: "s", Logic: prg.OR, Requirements: []prg.Requirement{
			expr("ok", "true"), expr("broken", "input.absent"),
		}}, nil)
		requireDeny(t, d, contracts.ReasonPRGEvalError)
	})
	t.Run("error in a child denies", func(t *testing.T) {
		d := decideSet(t, prg.RequirementSet{ID: "p", Logic: prg.OR, Requirements: []prg.Requirement{expr("ok", "true")},
			Children: []prg.RequirementSet{{ID: "c", Requirements: []prg.Requirement{expr("broken", "1 / 0 == 1")}}}}, nil)
		requireDeny(t, d, contracts.ReasonPRGEvalError)
	})
	t.Run("unserializable attributes", func(t *testing.T) {
		d := decideSet(t, prg.RequirementSet{ID: "s", Requirements: []prg.Requirement{expr("r", "true")}}, map[string]any{"f": func() {}})
		requireDeny(t, d, contracts.ReasonPRGEvalError)
	})
	t.Run("unknown action", func(t *testing.T) {
		s, err := compileOne(t, prg.RequirementSet{ID: "s"})
		require.NoError(t, err)
		d := Decide(Input{Action: "other", Time: testTime}, s)
		requireDeny(t, d, contracts.ReasonNoPolicy)
		require.Equal(t, s.Digest(), d.SnapshotDigest)
	})
	t.Run("nil snapshot", func(t *testing.T) {
		requireDeny(t, Decide(Input{Action: "act", Time: testTime}, nil), contracts.ReasonPRGEvalError)
	})
	t.Run("zero authority time", func(t *testing.T) {
		s, err := compileOne(t, prg.RequirementSet{ID: "s", Requirements: []prg.Requirement{expr("r", "true")}})
		require.NoError(t, err)
		requireDeny(t, Decide(Input{Action: "act"}, s), contracts.ReasonPRGEvalError)
	})
}

// A rule that does not compile is refused at activation and denies its action;
// the other rules in the snapshot keep deciding.
func TestCompileErrorsDenyOnlyTheirAction(t *testing.T) {
	bad := map[string]prg.RequirementSet{
		"syntax":         {ID: "syntax", Requirements: []prg.Requirement{expr("r", "input.x ==")}},
		"no condition":   {ID: "open", Requirements: []prg.Requirement{{ID: "open"}}},
		"unknown logic":  {ID: "xor", Logic: "XOR", Requirements: []prg.Requirement{expr("r", "true")}},
		"bad child leaf": {ID: "p", Children: []prg.RequirementSet{{ID: "c", Requirements: []prg.Requirement{{ID: "open"}}}}},
	}
	for name, set := range bad {
		t.Run(name, func(t *testing.T) {
			g := prg.NewGraph()
			require.NoError(t, g.AddRule("bad", set))
			require.NoError(t, g.AddRule("good", prg.RequirementSet{ID: "good", Requirements: []prg.Requirement{expr("r", "true")}}))

			s, err := Compile(g)
			require.Error(t, err)
			require.Contains(t, err.Error(), "action bad")
			requireDeny(t, Decide(Input{Action: "bad", Time: testTime}, s), contracts.ReasonPRGEvalError)
			requireAllow(t, Decide(Input{Action: "good", Time: testTime}, s))
		})
	}
}

// E-09: a condition that iterates caller-sized input is bounded. Before the
// cost limit this ran to completion and allowed.
func TestDecideCostLimitDenies(t *testing.T) {
	set := prg.RequirementSet{ID: "s", Requirements: []prg.Requirement{expr("all-positive", "input.items.all(x, x > 0)")}}

	small := make([]int, 100)
	for i := range small {
		small[i] = 1
	}
	requireAllow(t, decideSet(t, set, map[string]any{"items": small}))

	large := make([]int, int(CostLimit))
	for i := range large {
		large[i] = 1
	}
	d := decideSet(t, set, map[string]any{"items": large})
	requireDeny(t, d, contracts.ReasonPRGEvalError)
	require.Contains(t, d.Detail, "cost limit exceeded")
}

// Decide owns the action and the authority time; attributes cannot replace
// them.
func TestDecideReservedKeysCannotBeOverridden(t *testing.T) {
	set := prg.RequirementSet{ID: "s", Requirements: []prg.Requirement{
		expr("r", fmt.Sprintf(`input.action == "act" && input.timestamp == %d`, testTime.Unix())),
	}}
	requireAllow(t, decideSet(t, set, map[string]any{KeyAction: "admin.override", KeyTimestamp: 0}))
}

func TestSnapshotDigest(t *testing.T) {
	build := func(order ...string) *Snapshot {
		g := prg.NewGraph()
		for _, action := range order {
			require.NoError(t, g.AddRule(action, prg.RequirementSet{ID: action, Requirements: []prg.Requirement{expr("r", "true")}}))
		}
		s, err := Compile(g)
		require.NoError(t, err)
		return s
	}

	a, b := build("x", "y"), build("y", "x")
	require.Equal(t, a.Digest(), b.Digest(), "digest must not depend on rule insertion order")
	require.True(t, strings.HasPrefix(a.Digest(), "sha256:"))
	require.NotEqual(t, a.Digest(), build("x").Digest())

	g := prg.NewGraph()
	require.NoError(t, g.AddRule("x", prg.RequirementSet{ID: "x", Requirements: []prg.Requirement{expr("r", "true")}}))
	require.NoError(t, g.AddRule("y", prg.RequirementSet{ID: "y", Requirements: []prg.Requirement{expr("r", "true")}}))
	content, err := g.ContentHash()
	require.NoError(t, err)
	sum := sha256.Sum256([]byte(Profile + "\n" + content))
	require.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), a.Digest(), "digest must pin the evaluation profile and the policy content")

	d := Decide(Input{Action: "x", Time: testTime}, a)
	require.Equal(t, a.Digest(), d.SnapshotDigest)
	rule := g.Rules["x"]
	require.Equal(t, rule.Hash(), d.RuleHash)
}

func TestCompileNilGraphDeniesEverything(t *testing.T) {
	s, err := Compile(nil)
	require.NoError(t, err)
	requireDeny(t, Decide(Input{Action: "anything", Time: testTime}, s), contracts.ReasonNoPolicy)
}
