// compare.go implements execution trace comparison for governance determinism verification.
// Per arXiv 2601.00481 (MAESTRO), call graph comparison reveals governance differences.
//
// Given two governance traces (lists of TraceEntry records), produce a diff showing
// where decisions diverged.
//
// Design invariants:
//   - Comparison is deterministic
//   - Diffs include both matching and diverging decisions
//   - Thread-safe (operates on immutable snapshots)
package replay

// TraceDiff summarizes the comparison between two governance traces.
type TraceDiff struct {
	SessionA       string         `json:"session_a"`
	SessionB       string         `json:"session_b"`
	TotalA         int            `json:"total_a"`
	TotalB         int            `json:"total_b"`
	MatchCount     int            `json:"match_count"`
	DivergentCount int            `json:"divergent_count"`
	OnlyInA        int            `json:"only_in_a"`
	OnlyInB        int            `json:"only_in_b"`
	Divergences    []DecisionDiff `json:"divergences,omitempty"`
	Identical      bool           `json:"identical"`
}

// DecisionDiff describes a single point of divergence between two traces
// where the same (action, resource) pair produced different verdicts.
type DecisionDiff struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	VerdictA string `json:"verdict_a"`
	VerdictB string `json:"verdict_b"`
	ReasonA  string `json:"reason_a,omitempty"`
	ReasonB  string `json:"reason_b,omitempty"`
}

// TraceEntry represents a single governance decision in a trace.
type TraceEntry struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Verdict  string `json:"verdict"`
	Reason   string `json:"reason,omitempty"`
}

// traceKey builds a canonical lookup key from an action and resource.
func traceKey(action, resource string) string {
	return action + "\x00" + resource
}

// CompareTraces compares two governance traces and returns a deterministic diff.
// Entries are matched by (action, resource) pair. Where both traces contain
// the same pair, verdicts are compared. Entries present in only one trace are
// counted as only-in-A or only-in-B.
//
// If multiple entries in the same trace share the same (action, resource) key,
// only the last occurrence is considered for matching purposes.
func CompareTraces(sessionA string, traceA []TraceEntry, sessionB string, traceB []TraceEntry) *TraceDiff {
	diff := &TraceDiff{
		SessionA: sessionA,
		SessionB: sessionB,
		TotalA:   len(traceA),
		TotalB:   len(traceB),
	}

	// Build lookup maps. Last occurrence wins for duplicate keys.
	mapA := make(map[string]TraceEntry, len(traceA))
	for _, e := range traceA {
		mapA[traceKey(e.Action, e.Resource)] = e
	}

	mapB := make(map[string]TraceEntry, len(traceB))
	for _, e := range traceB {
		mapB[traceKey(e.Action, e.Resource)] = e
	}

	// Compare entries present in both, track only-in-A.
	for key, entryA := range mapA {
		entryB, inB := mapB[key]
		if !inB {
			diff.OnlyInA++
			continue
		}

		if entryA.Verdict == entryB.Verdict {
			diff.MatchCount++
		} else {
			diff.DivergentCount++
			diff.Divergences = append(diff.Divergences, DecisionDiff{
				Action:   entryA.Action,
				Resource: entryA.Resource,
				VerdictA: entryA.Verdict,
				VerdictB: entryB.Verdict,
				ReasonA:  entryA.Reason,
				ReasonB:  entryB.Reason,
			})
		}
	}

	// Count entries only in B.
	for key := range mapB {
		if _, inA := mapA[key]; !inA {
			diff.OnlyInB++
		}
	}

	diff.Identical = diff.DivergentCount == 0 && diff.OnlyInA == 0 && diff.OnlyInB == 0

	return diff
}
