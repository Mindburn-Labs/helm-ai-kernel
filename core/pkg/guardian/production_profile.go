package guardian

import (
	"fmt"
	"sort"
	"strings"

	pkg_artifact "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

const productionGateProfileName = "production-core-v1"

// GateProfile declares which Guardian gates are mandatory at a construction
// boundary and why the remaining declared gates are outside that profile.
// A gate may still be injected when it is de-scoped; de-scoping only means the
// gate is conditional on a product-specific authority that is not universal to
// every Kernel production entrypoint.
type GateProfile struct {
	Name     string
	Required []GateID
	DeScoped map[GateID]string
}

// ProductionGateProfile returns the universal six-gate enforcement profile
// documented by the Kernel: Freeze -> Context -> Identity -> Egress -> Threat
// -> Delegation. Product-specific gates remain explicit rather than silently
// disappearing when their backing authorities are not configured.
func ProductionGateProfile() GateProfile {
	return GateProfile{
		Name: productionGateProfileName,
		Required: []GateID{
			GateFreeze,
			GateContext,
			GateIsolation,
			GateEgress,
			GateThreat,
			GateDelegation,
		},
		DeScoped: map[GateID]string{
			GateAgentKillSwitch:    "requires an operator-managed per-agent stop authority; the universal profile retains the global freeze gate",
			GateAssumption:         "applies only to decisions carrying source-owned observations and requires their authoritative re-reader",
			GateAudit:              "signed decisions and entrypoint receipt stores are authoritative; the in-process AuditLog is an optional diagnostic sink",
			GateBehavioralTrust:    "requires a deployment-owned behavioral event history and tenant trust policy",
			GateBudget:             "requires a product-owned budget ledger and budget identity for the governed operation",
			GateCapabilityRegistry: "applies only to capability-mediated operations with an installed capability registry",
			GateCapabilityToken:    "applies only when a transport supplies a task-scoped capability token and verifier",
			GateCapabilityRollback: "applies only to effects whose capability contract requires a verified rollback plan",
			GateCompliance:         "requires a tenant and regulatory-regime-specific compliance authority",
			GatePDP:                "the local PRG remains the universal policy authority; an external PDP is deployment-specific",
			GatePolicySnapshots:    "requires a configured dynamic policy source; static fail-closed PRG operation remains supported",
			GatePrivilege:          "requires a tenant identity directory that resolves authoritative privilege tiers",
			GateSafeDeprecation:    "applies only to release and deprecation operations with a SafeDep authority",
			GateScopedStop:         "requires a durable tenant/workspace stop store; supporting server deployments inject it as an additional gate",
			GateSessionRisk:        "requires authoritative session history and a deployment-owned persistence boundary",
			GateTemporal:           "requires a source-owned temporal/replay policy for the operation class",
			GateWarmLease:          "applies only to sandbox allocations when the warm-pool subsystem is enabled",
		},
	}
}

// ValidateDefinition ratchets a profile against the complete declared gate
// universe. Every GateID must be classified exactly once, and every de-scoped
// gate must carry an auditable rationale.
func (p GateProfile) ValidateDefinition() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("guardian: gate profile name is required")
	}

	known := make(map[GateID]struct{}, len(AllGateIDs()))
	for _, id := range AllGateIDs() {
		known[id] = struct{}{}
	}
	classified := make(map[GateID]string, len(known))
	for _, id := range p.Required {
		if _, ok := known[id]; !ok {
			return fmt.Errorf("guardian: profile %q requires unknown gate %q", p.Name, id)
		}
		if disposition, duplicate := classified[id]; duplicate {
			return fmt.Errorf("guardian: profile %q classifies gate %q more than once (already %s)", p.Name, id, disposition)
		}
		classified[id] = "required"
	}
	for id, reason := range p.DeScoped {
		if _, ok := known[id]; !ok {
			return fmt.Errorf("guardian: profile %q de-scopes unknown gate %q", p.Name, id)
		}
		if strings.TrimSpace(reason) == "" {
			return fmt.Errorf("guardian: profile %q de-scopes gate %q without a rationale", p.Name, id)
		}
		if disposition, duplicate := classified[id]; duplicate {
			return fmt.Errorf("guardian: profile %q classifies gate %q more than once (already %s)", p.Name, id, disposition)
		}
		classified[id] = "de-scoped"
	}

	var unclassified []GateID
	for id := range known {
		if _, ok := classified[id]; !ok {
			unclassified = append(unclassified, id)
		}
	}
	if len(unclassified) > 0 {
		sort.Slice(unclassified, func(i, j int) bool { return unclassified[i] < unclassified[j] })
		return fmt.Errorf("guardian: profile %q leaves gates unclassified: %v", p.Name, unclassified)
	}
	return nil
}

// IncompleteGateProfileError reports the enforcement dependencies that kept a
// production Guardian from being constructed.
type IncompleteGateProfileError struct {
	Profile string
	Missing []GateID
}

func (e *IncompleteGateProfileError) Error() string {
	return fmt.Sprintf("guardian: gate profile %q is incomplete; missing required gates: %v", e.Profile, e.Missing)
}

// NewProductionGuardian constructs a Guardian only when the universal
// production enforcement roster is complete. NewGuardian intentionally
// remains available for focused tests, analysis commands, and development
// compositions that exercise a partial pipeline.
func NewProductionGuardian(signer crypto.Signer, ruleGraph *prg.Graph, reg *pkg_artifact.Registry, opts ...GuardianOption) (*Guardian, error) {
	profile := ProductionGateProfile()
	if err := profile.ValidateDefinition(); err != nil {
		return nil, err
	}

	g := NewGuardian(signer, ruleGraph, reg, opts...)
	active := make(map[GateID]bool, len(g.GateRoster().Active))
	for _, id := range g.GateRoster().Active {
		active[id] = true
	}

	var missing []GateID
	for _, id := range profile.Required {
		present := active[id]
		if id == GateThreat {
			// Semantic escalation is a useful threat control, but it cannot
			// replace the deterministic scanner required by this profile.
			present = g.threatScanner != nil
		}
		if !present {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })
		return nil, &IncompleteGateProfileError{Profile: profile.Name, Missing: missing}
	}
	return g, nil
}
