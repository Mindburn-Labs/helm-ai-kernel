package approvalceremony

// quantum_posture: tests classical SHA-256 reconciliation-fence receipt
// integrity; no hybrid or post-quantum claim.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
)

func TestVerifyCurrentEffectReconciliationFenceRejectsMismatchedReceipt(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	fence := kernel.FenceState{
		StopScope:       kernel.StopScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"},
		ContractVersion: kernel.EmergencyStopFenceContractVersion,
		Audience:        "helm-control-plane",
		KeyID:           "control-plane-a",
		CommandID:       "fence-a",
		CommandHash:     "sha256:" + hex.EncodeToString(make([]byte, 32)),
		Epoch:           1,
		ActorID:         "operator-a",
		Reason:          "contain active work",
		IssuedAt:        now.Add(-time.Minute),
		ExpiresAt:       now.Add(time.Minute),
		FencedAt:        now,
		AcknowledgementIdentity: kernel.AcknowledgementIdentity{
			KeyID: "kernel-a", SignerProfile: kernel.EmergencyStopSignerClassical, PublicKey: "ed25519:kernel-a",
		},
	}
	payload, err := fence.AcknowledgementPayload()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	fence.ReceiptHash = "sha256:" + hex.EncodeToString(sum[:])
	if err := verifyCurrentEffectReconciliationFence(fence); err != nil {
		t.Fatal(err)
	}
	fence.ReceiptHash = "sha256:" + hex.EncodeToString(make([]byte, 32))
	if err := verifyCurrentEffectReconciliationFence(fence); !errors.Is(err, ErrEffectDispositionConflict) {
		t.Fatalf("mismatched fence receipt error = %v", err)
	}
}
