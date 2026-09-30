package main

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/firewall"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/identity"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/threatscan"
)

// productionGuardianState is the durable stop state every production Guardian
// reads. Each entry point names it, so none can build a Guardian that misses a
// stop the others honour.
type productionGuardianState struct {
	// DataDir holds freeze_state.json, the global freeze that `helm-ai-kernel
	// freeze --data-dir` writes. Empty means HELM_DATA_DIR, then ./data.
	DataDir string
	// Stops is the scoped emergency-stop fence store, required while
	// HELM_EMERGENCY_STOP_FENCE_ENABLED is on.
	Stops kernel.ScopedStopReader
}

// newProductionGuardian is the shared construction boundary for the server,
// proxy, and local MCP runtimes. The egress checker starts deny-all; a trusted
// transport context must name a destination before it can be evaluated, and no
// destination is allowed until a deployment supplies a narrower policy.
func newProductionGuardian(
	signer crypto.Signer,
	ruleGraph *prg.Graph,
	registry *artifacts.Registry,
	clock guardian.Clock,
	state productionGuardianState,
	extraOptions ...guardian.GuardianOption,
) (*guardian.Guardian, error) {
	if clock == nil {
		return nil, fmt.Errorf("production Guardian authority clock is required")
	}
	if emergencyStopFenceEnabled() && state.Stops == nil {
		return nil, fmt.Errorf("%s is on but this Guardian has no scoped emergency-stop store", emergencyStopFenceEnabledEnv)
	}
	dataDir := state.DataDir
	freezeController := kernel.NewFreezeController().WithClock(clock.Now).WithStateSource(func() (kernel.FreezeStateSnapshot, error) {
		persisted, err := loadFreezeState(dataDir)
		if err != nil {
			return kernel.FreezeStateSnapshot{}, err
		}
		return kernel.FreezeStateSnapshot{
			Frozen:   persisted.Frozen,
			FrozenBy: persisted.FrozenBy,
			FrozenAt: persisted.FrozenAt,
		}, nil
	})
	if err := freezeController.RefreshState(); err != nil {
		return nil, fmt.Errorf("load production freeze state: %w", err)
	}

	options := []guardian.GuardianOption{
		guardian.WithClock(clock),
		guardian.WithFreezeController(freezeController),
		guardian.WithContextGuard(kernel.NewContextGuard().WithClock(clock.Now)),
		guardian.WithIsolationChecker(identity.NewIsolationChecker().WithClock(clock.Now)),
		guardian.WithEgressChecker(firewall.NewEgressChecker(nil).WithClock(clock.Now)),
		guardian.WithThreatScanner(threatscan.New(threatscan.WithClock(clock.Now))),
		guardian.WithDelegationStore(identity.NewInMemoryDelegationStore()),
	}
	if state.Stops != nil {
		options = append(options, guardian.WithScopedStopReader(state.Stops))
	}
	options = append(options, extraOptions...)

	return guardian.NewProductionGuardian(signer, ruleGraph, registry, options...)
}
