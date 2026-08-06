package promotionpermit

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestVerifyRejectsWrongEffectBeforeAuthorityResolution(t *testing.T) {
	err := Verify(contracts.LaunchEffectAuthorizationEnvelope{EffectID: contracts.EffectTypeProviderProvision}, VerificationContext{})
	if err == nil || !strings.Contains(err.Error(), contracts.EffectTypeDeployProductionActivate) {
		t.Fatalf("Verify() error = %v, want effect rejection", err)
	}
}

func TestVerifyCurrentFenceFailsClosed(t *testing.T) {
	envelope := contracts.LaunchEffectAuthorizationEnvelope{TenantID: "tenant-1", WorkspaceID: "workspace-1", EmergencyFenceEpoch: 7}
	for _, test := range []struct {
		name     string
		snapshot contracts.LaunchEmergencyFenceSnapshot
		want     string
	}{
		{name: "stale", snapshot: contracts.LaunchEmergencyFenceSnapshot{TenantID: "tenant-1", WorkspaceID: "workspace-1", EffectiveEpoch: 6}, want: "mismatch"},
		{name: "active", snapshot: contracts.LaunchEmergencyFenceSnapshot{TenantID: "tenant-1", WorkspaceID: "workspace-1", EffectiveEpoch: 7, Active: true}, want: "active"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := verifyCurrentFence(envelope, contracts.LaunchEffectEnvelopeVerificationContext{
				ResolveEmergencyFence: func(string, string) (contracts.LaunchEmergencyFenceSnapshot, error) { return test.snapshot, nil },
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verifyCurrentFence() error = %v, want substring %q", err, test.want)
			}
		})
	}
}
