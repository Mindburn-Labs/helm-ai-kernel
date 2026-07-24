package guardian

import (
	"reflect"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
)

// gateFieldByID maps each declared gate to the Guardian field its call sites
// nil-check. It lives in the test so production code carries no reflection.
var gateFieldByID = map[GateID]string{
	GateAgentKillSwitch: "agentKillSwitch",
	GateAudit:           "auditLog",
	GateBehavioralTrust: "behavioralScorer",
	GateBudget:          "tracker",
	GateCompliance:      "complianceChecker",
	GateContext:         "contextGuard",
	GateDelegation:      "delegationStore",
	GateEgress:          "egressChecker",
	GateFreeze:          "freezeCtrl",
	GateIsolation:       "isolationChecker",
	GatePDP:             "pdp",
	GatePolicySnapshots: "snapshotStore",
	GatePrivilege:       "privilegeResolver",
	GateSafeDeprecation: "safeDepController",
	GateScopedStop:      "scopedStopReader",
	GateSessionRisk:     "sessionRiskMemory",
	GateTemporal:        "temporal",
	GateThreat:          "threatScanner",
	GateWarmLease:       "warmLeaseMgr",
}

// nonGateFields are Guardian fields that are not injectable gates: core
// collaborators the Guardian cannot run without, or derived state. They are
// listed explicitly so that adding a field forces a deliberate choice between
// "this is a gate" and "this is not".
var nonGateFields = map[string]bool{
	"signer":            true,
	"prg":               true,
	"pe":                true,
	"registry":          true,
	"clock":             true,
	"envFprint":         true,
	"snapshotScope":     true,
	"otel":              true,
	"zeroidInterceptor": true,
	"boundaryChain":     true,
}

// A new nil-gated dependency added to Guardian without a GateID would be
// invisible to the roster — and an invisible gate is how fourteen of them came
// to be unset in every production path. This fails until it is classified.
func TestGateRosterCoversEveryGuardianGateField(t *testing.T) {
	mapped := make(map[string]GateID, len(gateFieldByID))
	for id, field := range gateFieldByID {
		if prev, dup := mapped[field]; dup {
			t.Fatalf("field %q mapped by both %q and %q", field, prev, id)
		}
		mapped[field] = id
	}

	structType := reflect.TypeOf(Guardian{})
	for i := 0; i < structType.NumField(); i++ {
		name := structType.Field(i).Name
		if nonGateFields[name] {
			continue
		}
		if _, ok := mapped[name]; !ok {
			t.Errorf("Guardian field %q has no GateID and is not listed in nonGateFields; "+
				"classify it so the roster stays complete", name)
		}
	}

	for field := range mapped {
		if _, ok := structType.FieldByName(field); !ok {
			t.Errorf("gateFieldByID references %q, which is not a Guardian field", field)
		}
	}

	if len(AllGateIDs()) != len(gateFieldByID) {
		t.Fatalf("AllGateIDs has %d entries, gateFieldByID has %d", len(AllGateIDs()), len(gateFieldByID))
	}
}

// Pins the audit baseline: constructed with no options, every gate is skipped.
// Production call sites pass at most three options, so this is close to what
// actually ships. If a gate becomes injected by default, this test should be
// updated deliberately rather than by accident.
func TestGateRosterReportsEveryGateInactiveWithoutOptions(t *testing.T) {
	g := NewGuardian(nil, nil, nil)

	roster := g.GateRoster()
	if len(roster.Active) != 0 {
		t.Errorf("Active = %v, want none for an option-less Guardian", roster.Active)
	}
	if len(roster.Inactive) != len(AllGateIDs()) {
		t.Errorf("Inactive has %d gates, want all %d", len(roster.Inactive), len(AllGateIDs()))
	}
}

// The roster is only useful as evidence if it hashes deterministically.
func TestGateRosterHashIsDeterministicAndDistinguishesComposition(t *testing.T) {
	bare := NewGuardian(nil, nil, nil)
	bareHash, err := bare.GateRoster().Hash()
	if err != nil {
		t.Fatalf("hashing bare roster: %v", err)
	}
	repeatHash, err := NewGuardian(nil, nil, nil).GateRoster().Hash()
	if err != nil {
		t.Fatalf("hashing repeat roster: %v", err)
	}
	if bareHash != repeatHash {
		t.Fatalf("roster hash is not deterministic: %q vs %q", bareHash, repeatHash)
	}

	withFreeze := NewGuardian(nil, nil, nil, WithFreezeController(kernel.NewFreezeController()))
	freezeRoster := withFreeze.GateRoster()
	freezeHash, err := freezeRoster.Hash()
	if err != nil {
		t.Fatalf("hashing freeze roster: %v", err)
	}
	if freezeHash == bareHash {
		t.Fatal("roster hash did not change when a gate was injected")
	}
	for _, id := range freezeRoster.Active {
		if id == GateFreeze {
			return
		}
	}
	t.Fatalf("Active = %v, want it to contain %q", freezeRoster.Active, GateFreeze)
}
