package guardian

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// modelGateToID maps each gate in the TLA+ model (proofs/guardian.cfg) to the
// GateID it stands for.
//
// GuardianPipeline.tla proves AllowRequiresUnanimity over exactly this set and
// has no state for an absent gate. That proof therefore says something about
// the shipped kernel only while these names still correspond to real gates —
// a rename or a spec edit silently narrows what TLC checks without failing
// anything. This test is the correspondence check.
var modelGateToID = map[string]GateID{
	"G0_Freeze":     GateFreeze,
	"G1_Context":    GateContext,
	"G2_Identity":   GateIsolation, // identity.IsolationChecker — credential reuse
	"G3_Egress":     GateEgress,
	"G4_Threat":     GateThreat,
	"G5_Delegation": GateDelegation,
}

var cfgGatesRe = regexp.MustCompile(`(?m)^\s*Gates\s*=\s*\{([^}]*)\}`)

func modelGates(t *testing.T) []string {
	t.Helper()

	path := filepath.Join("..", "..", "..", "proofs", "guardian.cfg")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	m := cfgGatesRe.FindSubmatch(raw)
	if m == nil {
		t.Fatalf("no `Gates = {...}` assignment in %s; the model's gate set moved", path)
	}

	var gates []string
	for _, part := range strings.Split(string(m[1]), ",") {
		if g := strings.TrimSpace(part); g != "" {
			gates = append(gates, g)
		}
	}
	if len(gates) == 0 {
		t.Fatalf("empty gate set in %s: TLC would prove unanimity over nothing", path)
	}
	return gates
}

// TestModelGateSetMatchesDeclaredGates fails when the TLA+ model and the Go
// gate declarations drift apart in either direction.
func TestModelGateSetMatchesDeclaredGates(t *testing.T) {
	gates := modelGates(t)

	declared := make(map[GateID]bool, len(AllGateIDs()))
	for _, id := range AllGateIDs() {
		declared[id] = true
	}

	seen := make(map[string]bool, len(gates))
	for _, gate := range gates {
		seen[gate] = true

		id, mapped := modelGateToID[gate]
		if !mapped {
			t.Errorf("model gate %q has no GateID mapping: TLC proves a property about a gate the kernel does not declare", gate)
			continue
		}
		if !declared[id] {
			t.Errorf("model gate %q maps to GateID %q, which is not in AllGateIDs(): the gate was renamed or removed", gate, id)
		}
	}

	for gate := range modelGateToID {
		if !seen[gate] {
			t.Errorf("gate %q is mapped here but absent from proofs/guardian.cfg: the model no longer checks it", gate)
		}
	}
}

// TestGateRosterHashIsDeterministic pins the property the decision record
// depends on: the same gate set always digests to the same value, so a
// roster hash is comparable across kernels. Roster completeness itself is
// covered by TestGateRosterCoversEveryGuardianGateField.
func TestGateRosterHashIsDeterministic(t *testing.T) {
	g := &Guardian{}
	roster := g.GateRoster()

	first, err := roster.Hash()
	if err != nil {
		t.Fatalf("hash roster: %v", err)
	}
	second, err := g.GateRoster().Hash()
	if err != nil {
		t.Fatalf("rehash roster: %v", err)
	}
	if first != second {
		t.Errorf("roster hash is not deterministic: %q then %q", first, second)
	}
	if !strings.HasPrefix(first, "sha256:") {
		t.Errorf("roster hash %q is not a sha256 digest", first)
	}
}
