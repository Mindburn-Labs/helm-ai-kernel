package keystore

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestRotationEventHash(t *testing.T) {
	event := RotationEvent{
		EventID:       "event-1",
		EventType:     RotationEventGenerate,
		KID:           "new",
		Algorithm:     "ed25519",
		Purpose:       PurposeSigning,
		Timestamp:     time.Unix(100, 0).UTC(),
		AuthorizedBy:  "old",
		PublicKeyHash: "sha256:abc",
		Reason:        "routine",
	}

	hash, err := event.Hash()
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("Hash() = %q", hash)
	}

	restore := replaceRotationHooks(t)
	marshalRotationEvent = func(any) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}
	_, err = event.Hash()
	if err == nil || !strings.Contains(err.Error(), "failed to marshal") {
		t.Fatalf("Hash() injected error = %v", err)
	}
	restore()
}

func TestRotationExecutorRotate(t *testing.T) {
	fixed := time.Unix(1700000000, 123).UTC()
	empty := NewMemoryKeyProvider()
	_, err := NewRotationExecutor(empty).WithClock(func() time.Time { return fixed }).Rotate(rotationPlan("new", "old"))
	if err == nil || !strings.Contains(err.Error(), "no active key") {
		t.Fatalf("Rotate() without active key error = %v", err)
	}

	provider := NewMemoryKeyProvider()
	if _, err := provider.GenerateKey("old"); err != nil {
		t.Fatalf("GenerateKey(old) error = %v", err)
	}
	receipt, err := NewRotationExecutor(provider).WithClock(func() time.Time { return fixed }).Rotate(rotationPlan("new", "old"))
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if receipt.Event.EventType != RotationEventGenerate || receipt.Event.KID != "new" || receipt.Event.AuthorizedBy != "old" {
		t.Fatalf("rotation event = %#v", receipt.Event)
	}
	if receipt.AuthorizerKID != "old" || !strings.HasPrefix(receipt.EventHash, "sha256:") {
		t.Fatalf("receipt = %#v", receipt)
	}
	sig, err := hex.DecodeString(receipt.AuthorizerSig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("AuthorizerSig = %q, decoded len %d, err %v", receipt.AuthorizerSig, len(sig), err)
	}
	if _, err := provider.SignerByKID("old"); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("old key should be revoked, err = %v", err)
	}
	if _, err := provider.SignerByKID("new"); err != nil {
		t.Fatalf("new key should be available: %v", err)
	}
}

func TestRotationExecutorFailureBranches(t *testing.T) {
	t.Run("generate new key", func(t *testing.T) {
		provider := NewMemoryKeyProvider()
		if _, err := provider.GenerateKey("old"); err != nil {
			t.Fatalf("GenerateKey(old) error = %v", err)
		}

		restore := replaceProviderHooks(t)
		newEd25519Signer = func(string) (*helmcrypto.Ed25519Signer, error) {
			return nil, errors.New("generate failed")
		}
		defer restore()

		_, err := NewRotationExecutor(provider).Rotate(rotationPlan("new", "old"))
		if err == nil || !strings.Contains(err.Error(), "failed to generate new key") {
			t.Fatalf("Rotate() generate error = %v", err)
		}
	})

	t.Run("hash event", func(t *testing.T) {
		provider := NewMemoryKeyProvider()
		if _, err := provider.GenerateKey("old"); err != nil {
			t.Fatalf("GenerateKey(old) error = %v", err)
		}

		restore := replaceRotationHooks(t)
		marshalRotationEvent = func(any) ([]byte, error) {
			return nil, errors.New("hash failed")
		}
		defer restore()

		_, err := NewRotationExecutor(provider).Rotate(rotationPlan("new", "old"))
		if err == nil || !strings.Contains(err.Error(), "failed to hash rotation event") {
			t.Fatalf("Rotate() hash error = %v", err)
		}
	})

	t.Run("sign event", func(t *testing.T) {
		provider := NewMemoryKeyProvider()
		provider.signers["old"] = fakeSigner{
			kid:       "old",
			publicKey: make([]byte, ed25519.PublicKeySize),
			signErr:   errors.New("sign failed"),
		}
		provider.metas["old"] = KeyMeta{KID: "old", Algorithm: "ed25519", Purpose: PurposeSigning, CreatedAt: time.Now()}
		provider.ordered = []string{"old"}

		_, err := NewRotationExecutor(provider).Rotate(rotationPlan("new", "old"))
		if err == nil || !strings.Contains(err.Error(), "failed to sign rotation event") {
			t.Fatalf("Rotate() sign error = %v", err)
		}
	})

	t.Run("revoke old key", func(t *testing.T) {
		provider := NewMemoryKeyProvider()
		if _, err := provider.GenerateKey("old"); err != nil {
			t.Fatalf("GenerateKey(old) error = %v", err)
		}

		_, err := NewRotationExecutor(provider).Rotate(rotationPlan("new", "missing-old"))
		if err == nil || !strings.Contains(err.Error(), "failed to revoke old key") {
			t.Fatalf("Rotate() revoke error = %v", err)
		}
	})
}

func rotationPlan(newKID, replacesKID string) *RotationPlan {
	return &RotationPlan{
		PlanID:      "plan-1",
		NewKID:      newKID,
		ReplacesKID: replacesKID,
		Algorithm:   "ed25519",
		Purpose:     PurposeSigning,
		Reason:      "routine",
	}
}

func replaceRotationHooks(t *testing.T) func() {
	t.Helper()

	oldMarshalRotationEvent := marshalRotationEvent
	restored := false

	restore := func() {
		if restored {
			return
		}
		marshalRotationEvent = oldMarshalRotationEvent
		restored = true
	}
	t.Cleanup(restore)
	return restore
}
