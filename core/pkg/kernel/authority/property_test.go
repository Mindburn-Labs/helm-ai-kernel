package authority

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

// Property tests use fixed seeds so a failure reproduces exactly.
const propertyRuns = 500

func newRand(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)) }

func randomDuration(r *rand.Rand) time.Duration {
	return time.Duration(r.IntN(1_000_000)) * time.Second
}

// ref is an independent reference evaluator for requirement trees whose leaves
// read boolean attributes.
func ref(set prg.RequirementSet, attrs map[string]any) bool {
	if len(set.Requirements) == 0 && len(set.Children) == 0 {
		return true
	}
	var results []bool
	for _, req := range set.Requirements {
		results = append(results, attrs[req.ID].(bool))
	}
	for _, child := range set.Children {
		results = append(results, ref(child, attrs))
	}
	allTrue, anyTrue := true, false
	for _, r := range results {
		allTrue = allTrue && r
		anyTrue = anyTrue || r
	}
	switch set.Logic {
	case prg.OR:
		return anyTrue
	case prg.NOT:
		return !allTrue
	default:
		return allTrue
	}
}

var logics = []prg.LogicOperator{prg.AND, prg.OR, prg.NOT, ""}

// randomTree builds a requirement tree whose leaf i reads input.<leaf id>.
func randomTree(r *rand.Rand, depth int, next *int) prg.RequirementSet {
	set := prg.RequirementSet{ID: fmt.Sprintf("set%d", *next), Logic: logics[r.IntN(len(logics))]}
	*next++
	for range r.IntN(4) {
		id := fmt.Sprintf("b%d", *next)
		*next++
		set.Requirements = append(set.Requirements, expr(id, "input."+id))
	}
	if depth > 0 {
		for range r.IntN(3) {
			set.Children = append(set.Children, randomTree(r, depth-1, next))
		}
	}
	return set
}

func leafIDs(set prg.RequirementSet, into map[string]bool) {
	into[set.ID] = true
	for _, req := range set.Requirements {
		into[req.ID] = true
	}
	for _, child := range set.Children {
		leafIDs(child, into)
	}
}

// Random AND/OR/NOT trees over random boolean attributes decide exactly as the
// reference evaluator does, and every denial names requirements of the rule.
func TestPropertyLogicMatchesReference(t *testing.T) {
	r := newRand(1)
	for run := range propertyRuns {
		next := 0
		set := randomTree(r, 3, &next)
		attrs := map[string]any{}
		for i := range next {
			attrs[fmt.Sprintf("b%d", i)] = r.IntN(2) == 1
		}

		d := decideSet(t, set, attrs)
		if ref(set, attrs) {
			require.Equal(t, contracts.VerdictAllow, d.Verdict, "run %d: %+v", run, set)
			continue
		}
		requireDeny(t, d, contracts.ReasonMissingRequirement)
		require.NotEmpty(t, d.Unmet, "run %d", run)
		known := map[string]bool{}
		leafIDs(set, known)
		for _, id := range d.Unmet {
			require.True(t, known[id], "run %d: unmet %q is not a requirement of the rule", run, id)
		}
	}
}

func randomValue(r *rand.Rand, depth int) any {
	switch n := r.IntN(8); {
	case n == 0:
		return nil
	case n == 1:
		return r.IntN(2) == 1
	case n == 2:
		return r.IntN(1000) - 500
	case n == 3:
		return r.Float64() * 100
	case n == 4 || depth == 0:
		return fmt.Sprintf("s%d", r.IntN(20))
	case n == 5:
		list := make([]any, r.IntN(4))
		for i := range list {
			list[i] = randomValue(r, depth-1)
		}
		return list
	default:
		return randomDoc(r, depth-1)
	}
}

func randomDoc(r *rand.Rand, depth int) map[string]any {
	doc := map[string]any{}
	for range r.IntN(5) {
		doc[fmt.Sprintf("k%d", r.IntN(6))] = randomValue(r, depth)
	}
	return doc
}

// Conditions that read random documents: some are satisfied, some are not,
// and some fail on a missing key or a type mismatch.
var probes = []string{
	`has(input.k0)`,
	`input.k0 == "s1"`,
	`input.k1 > 10`,
	`size(input) > 4`,
	`input.exists(k, k == "k2")`,
	`input.k3.k0 == true`,
	`input.k4.size() >= 2`,
	`input.timestamp > 0 && input.action == "act"`,
}

func randomProbeSet(r *rand.Rand) prg.RequirementSet {
	set := prg.RequirementSet{ID: "probe", Logic: logics[r.IntN(len(logics))]}
	for i := range 1 + r.IntN(3) {
		set.Requirements = append(set.Requirements, expr(fmt.Sprintf("p%d", i), probes[r.IntN(len(probes))]))
	}
	return set
}

// Replay: a decision is a pure function of the stored input. Deciding again,
// or deciding the input after a JSON round trip through storage, reproduces
// the same decision; and every decision is well formed.
func TestPropertyReplayIsExact(t *testing.T) {
	r := newRand(2)
	seen := map[contracts.ReasonCode]int{}
	for run := range propertyRuns {
		s, err := compileOne(t, randomProbeSet(r))
		require.NoError(t, err)
		in := Input{Action: "act", Attributes: randomDoc(r, 3), Time: testTime.Add(randomDuration(r))}

		live := Decide(in, s)
		require.Equal(t, live, Decide(in, s), "run %d: decide is not deterministic", run)

		stored, err := json.Marshal(in)
		require.NoError(t, err)
		var replayed Input
		require.NoError(t, json.Unmarshal(stored, &replayed))
		require.Equal(t, live, Decide(replayed, s), "run %d: replay diverged for %s", run, stored)

		switch live.Verdict {
		case contracts.VerdictAllow:
			require.Empty(t, live.ReasonCode, "run %d", run)
		case contracts.VerdictDeny:
			require.NotEmpty(t, live.ReasonCode, "run %d", run)
		default:
			t.Fatalf("run %d: unexpected verdict %q", run, live.Verdict)
		}
		require.Equal(t, s.Digest(), live.SnapshotDigest)
		seen[live.ReasonCode]++
	}
	// The property is vacuous unless the runs reach every outcome.
	for _, code := range []contracts.ReasonCode{"", contracts.ReasonMissingRequirement, contracts.ReasonPRGEvalError} {
		require.Positive(t, seen[code], "no run produced reason %q: %v", code, seen)
	}
}

// Attributes named like the reserved keys never change a decision.
func TestPropertyReservedKeysAreInert(t *testing.T) {
	r := newRand(3)
	for run := range propertyRuns {
		s, err := compileOne(t, randomProbeSet(r))
		require.NoError(t, err)
		attrs := randomDoc(r, 2)
		want := Decide(Input{Action: "act", Attributes: attrs, Time: testTime}, s)

		spoofed := map[string]any{KeyAction: randomValue(r, 1), KeyTimestamp: randomValue(r, 1)}
		for k, v := range attrs {
			spoofed[k] = v
		}
		require.Equal(t, want, Decide(Input{Action: "act", Attributes: spoofed, Time: testTime}, s), "run %d", run)
	}
}

// Default deny: any action without a rule is denied, whatever the input.
func TestPropertyUnknownActionDenies(t *testing.T) {
	r := newRand(4)
	s, err := compileOne(t, prg.RequirementSet{ID: "s"})
	require.NoError(t, err)
	for run := range propertyRuns {
		action := fmt.Sprintf("%x", r.Uint64())
		d := Decide(Input{Action: action, Attributes: randomDoc(r, 2), Time: testTime}, s)
		requireDeny(t, d, contracts.ReasonNoPolicy)
		require.Empty(t, d.Unmet, "run %d", run)
	}
}

// A snapshot is shared by every concurrent decision.
func TestPropertyConcurrentDecideAgrees(t *testing.T) {
	r := newRand(5)
	s, err := compileOne(t, randomProbeSet(r))
	require.NoError(t, err)
	inputs := make([]Input, 64)
	want := make([]Decision, len(inputs))
	for i := range inputs {
		inputs[i] = Input{Action: "act", Attributes: randomDoc(r, 2), Time: testTime}
		want[i] = Decide(inputs[i], s)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i, in := range inputs {
				if got := Decide(in, s); !decisionsEqual(got, want[i]) {
					t.Errorf("input %d: concurrent decision %+v, want %+v", i, got, want[i])
				}
			}
		}()
	}
	wg.Wait()
}

func decisionsEqual(a, b Decision) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}
