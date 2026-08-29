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

// newProductionGuardian is the shared construction boundary for the server,
// proxy, and local MCP runtimes. The egress checker starts deny-all; a trusted
// transport context must name a destination before it can be evaluated, and no
// destination is allowed until a deployment supplies a narrower policy.
func newProductionGuardian(
	signer crypto.Signer,
	ruleGraph *prg.Graph,
	registry *artifacts.Registry,
	clock guardian.Clock,
	extraOptions ...guardian.GuardianOption,
) (*guardian.Guardian, error) {
	if clock == nil {
		return nil, fmt.Errorf("production Guardian authority clock is required")
	}
	freezeController := kernel.NewFreezeController().WithClock(clock.Now).WithStateSource(func() (kernel.FreezeStateSnapshot, error) {
		state, err := loadFreezeState()
		if err != nil {
			return kernel.FreezeStateSnapshot{}, err
		}
		return kernel.FreezeStateSnapshot{
			Frozen:   state.Frozen,
			FrozenBy: state.FrozenBy,
			FrozenAt: state.FrozenAt,
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
	options = append(options, extraOptions...)

	return guardian.NewProductionGuardian(signer, ruleGraph, registry, options...)
}
