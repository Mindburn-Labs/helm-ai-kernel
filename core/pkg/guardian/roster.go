package guardian

import (
	"sort"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// GateID names a Guardian dependency that gates authorization.
//
// Every gate is injected through a GuardianOption and every use site is written
// `if g.<field> != nil`, so an uninjected gate is silently skipped rather than
// refused. The roster below makes that composition observable: which gates a
// Guardian will actually run is otherwise only discoverable by reading each
// call site.
//
// proofs/GuardianPipeline.tla asserts AllowRequiresUnanimity over every gate
// and has no state for an absent one, so a nil gate is a refinement gap
// against a spec TLC checks on each PR. The roster hash binds composition into
// each decision, and NewProductionGuardian refuses a production profile whose
// required enforcement roster is incomplete.
type GateID string

const (
	GateBehavioralTrust GateID = "behavioral_trust"
	GateContext         GateID = "context"
	GateDelegation      GateID = "delegation"
	GateEgress          GateID = "egress"
	GateFreeze          GateID = "freeze"
	GateIsolation       GateID = "isolation"
	GatePDP             GateID = "pdp"
	GatePolicySnapshots GateID = "policy_snapshots"
	GateSafeDeprecation GateID = "safe_deprecation"
	GateScopedStop      GateID = "scoped_stop"
	GateTemporal        GateID = "temporal"
	GateThreat          GateID = "threat"
)

// GateRoster records which gates a Guardian will run and which it will skip.
//
// Both slices are sorted so the roster canonicalizes deterministically.
type GateRoster struct {
	Active   []GateID `json:"active"`
	Inactive []GateID `json:"inactive"`
}

// Hash returns the JCS/SHA-256 digest of the roster in wire form. It is the
// value intended to be bound into a decision record, so evidence states which
// gates produced a verdict instead of leaving that to code review.
func (r GateRoster) Hash() (string, error) {
	digest, err := canonicalize.CanonicalHash(r)
	if err != nil {
		return "", err
	}
	return "sha256:" + digest, nil
}

// GateRoster reports the gates injected into g. A gate is Active when its
// dependency or explicit configuration causes its call site to run.
func (g *Guardian) GateRoster() GateRoster {
	injected := map[GateID]bool{
		GateBehavioralTrust: g.behavioralScorer != nil,
		GateContext:         g.contextGuard != nil,
		GateDelegation:      g.delegationStore != nil,
		GateEgress:          g.egressChecker != nil,
		GateFreeze:          g.freezeCtrl != nil,
		GateIsolation:       g.isolationChecker != nil,
		GatePDP:             g.pdp != nil,
		GatePolicySnapshots: g.snapshotStore != nil,
		GateSafeDeprecation: g.safeDepController != nil,
		GateScopedStop:      g.scopedStopReader != nil,
		GateTemporal:        g.temporal != nil,
		GateThreat:          g.threatScanner != nil || g.semanticEscalationThresholdBP > 0,
	}

	roster := GateRoster{Active: []GateID{}, Inactive: []GateID{}}
	for id, present := range injected {
		if present {
			roster.Active = append(roster.Active, id)
		} else {
			roster.Inactive = append(roster.Inactive, id)
		}
	}
	sort.Slice(roster.Active, func(i, j int) bool { return roster.Active[i] < roster.Active[j] })
	sort.Slice(roster.Inactive, func(i, j int) bool { return roster.Inactive[i] < roster.Inactive[j] })
	return roster
}

// AllGateIDs returns every declared gate, sorted.
func AllGateIDs() []GateID {
	ids := []GateID{
		GateBehavioralTrust, GateContext, GateDelegation, GateEgress, GateFreeze,
		GateIsolation, GatePDP, GatePolicySnapshots, GateSafeDeprecation,
		GateScopedStop, GateTemporal, GateThreat,
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
