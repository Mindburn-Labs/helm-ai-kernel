package guardian

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/firewall"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/identity"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/threatscan"
)

func productionProfileTestSigner(t *testing.T) helmcrypto.Signer {
	t.Helper()
	signer, err := helmcrypto.NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x65}, 32), "production-profile-test")
	if err != nil {
		t.Fatalf("construct production profile test signer: %v", err)
	}
	return signer
}

func productionProfileOptions(omit GateID) []GuardianOption {
	options := []struct {
		id     GateID
		option GuardianOption
	}{
		{GateFreeze, WithFreezeController(kernel.NewFreezeController())},
		{GateContext, WithContextGuard(kernel.NewContextGuard())},
		{GateIsolation, WithIsolationChecker(identity.NewIsolationChecker())},
		{GateEgress, WithEgressChecker(firewall.NewEgressChecker(nil))},
		{GateThreat, WithThreatScanner(threatscan.New())},
		{GateDelegation, WithDelegationStore(identity.NewInMemoryDelegationStore())},
	}

	result := make([]GuardianOption, 0, len(options))
	for _, candidate := range options {
		if candidate.id != omit {
			result = append(result, candidate.option)
		}
	}
	return result
}

func TestProductionGateProfileClassifiesEveryDeclaredGate(t *testing.T) {
	profile := ProductionGateProfile()
	if err := profile.ValidateDefinition(); err != nil {
		t.Fatalf("production profile definition: %v", err)
	}

	classified := append([]GateID(nil), profile.Required...)
	for id, reason := range profile.DeScoped {
		if reason == "" {
			t.Errorf("de-scoped gate %q has no rationale", id)
		}
		classified = append(classified, id)
	}
	if len(classified) != len(AllGateIDs()) {
		t.Fatalf("classified %d gates, want %d", len(classified), len(AllGateIDs()))
	}
}

func TestNewProductionGuardianRejectsEachMissingRequiredGate(t *testing.T) {
	signer := productionProfileTestSigner(t)
	for _, missing := range ProductionGateProfile().Required {
		missing := missing
		t.Run(string(missing), func(t *testing.T) {
			got, err := NewProductionGuardian(signer, nil, nil, productionProfileOptions(missing)...)
			if got != nil {
				t.Fatal("incomplete production Guardian must not be returned")
			}
			var profileErr *IncompleteGateProfileError
			if !errors.As(err, &profileErr) {
				t.Fatalf("error = %v, want IncompleteGateProfileError", err)
			}
			if !reflect.DeepEqual(profileErr.Missing, []GateID{missing}) {
				t.Fatalf("missing = %v, want [%s]", profileErr.Missing, missing)
			}
		})
	}
}

func TestNewProductionGuardianRequiresConcreteThreatScanner(t *testing.T) {
	options := productionProfileOptions(GateThreat)
	options = append(options, WithSemanticThreatEscalation(5000))

	got, err := NewProductionGuardian(productionProfileTestSigner(t), nil, nil, options...)
	if got != nil {
		t.Fatal("semantic escalation without a scanner must not satisfy the production threat gate")
	}
	var profileErr *IncompleteGateProfileError
	if !errors.As(err, &profileErr) || !reflect.DeepEqual(profileErr.Missing, []GateID{GateThreat}) {
		t.Fatalf("error = %v, want missing concrete threat gate", err)
	}
}

func TestNewProductionGuardianAcceptsCompleteRequiredRoster(t *testing.T) {
	g, err := NewProductionGuardian(productionProfileTestSigner(t), nil, nil, productionProfileOptions("")...)
	if err != nil {
		t.Fatalf("construct complete production Guardian: %v", err)
	}
	if g == nil {
		t.Fatal("complete production Guardian is nil")
	}

	active := make(map[GateID]bool)
	for _, id := range g.GateRoster().Active {
		active[id] = true
	}
	for _, required := range ProductionGateProfile().Required {
		if !active[required] {
			t.Errorf("required gate %q is not active in accepted production roster", required)
		}
	}
}

func TestNewProductionGuardianRejectsNilSigner(t *testing.T) {
	var typedNil *helmcrypto.Ed25519Signer

	tests := []struct {
		name   string
		signer helmcrypto.Signer
	}{
		{name: "nil interface"},
		{name: "typed nil", signer: typedNil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			g, err := NewProductionGuardian(test.signer, nil, nil, productionProfileOptions("")...)
			if g != nil {
				t.Fatal("production Guardian with nil signer must not be returned")
			}
			var dependencyErr *MissingProductionDependencyError
			if !errors.As(err, &dependencyErr) {
				t.Fatalf("error = %v, want MissingProductionDependencyError", err)
			}
			if dependencyErr.Dependency != "decision signer" {
				t.Fatalf("dependency = %q, want decision signer", dependencyErr.Dependency)
			}
		})
	}
}

func TestNewGuardianStillAllowsPartialDevelopmentConstruction(t *testing.T) {
	if got := NewGuardian(nil, nil, nil); got == nil {
		t.Fatal("development constructor unexpectedly rejected a partial roster")
	}
}
