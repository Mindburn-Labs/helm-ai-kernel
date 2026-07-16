package approvalceremony

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestGrantSignatureBindsExactTrustRootAndGrant(t *testing.T) {
	_, _, _, grant := ceremonyFixtures(t)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	signer := crypto.NewEd25519SignerFromKey(privateKey, "approval-test")
	verifier, err := NewEd25519GrantSignatureVerifier(signer.PublicKeyBytes(), grant.SigningKeyRef, grant.KernelTrustRootID)
	if err != nil {
		t.Fatalf("NewEd25519GrantSignatureVerifier(): %v", err)
	}
	signature, err := SignApprovalGrant(grant, signer)
	if err != nil {
		t.Fatalf("SignApprovalGrant(): %v", err)
	}
	if err := verifier.VerifyGrantSignature(grant, GrantSignatureEd25519, signature); err != nil {
		t.Fatalf("VerifyGrantSignature(): %v", err)
	}
	payloadA, err := ApprovalGrantSigningPayload(grant, GrantSignatureEd25519)
	if err != nil {
		t.Fatal(err)
	}
	payloadB, err := ApprovalGrantSigningPayload(grant, GrantSignatureEd25519)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payloadA, payloadB) {
		t.Fatal("approval grant signing payload is not deterministic")
	}

	badSignature := signature[:len(signature)-2] + "00"
	if err := verifier.VerifyGrantSignature(grant, GrantSignatureEd25519, badSignature); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("tampered signature error = %v, want ErrGrantSignatureRejected", err)
	}
	mutated := grant
	mutated.SigningKeyRef = "kms://helm/other"
	mutated.GrantHash = ""
	mutated, err = mutated.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyGrantSignature(mutated, GrantSignatureEd25519, signature); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("trust-root substitution error = %v, want ErrGrantSignatureRejected", err)
	}
}

func TestGrantSigningAndStoreFailClosedWithoutTrust(t *testing.T) {
	_, _, _, grant := ceremonyFixtures(t)
	if _, err := SignApprovalGrant(grant, nil); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("nil signer error = %v, want ErrGrantSignatureRejected", err)
	}
	store := NewPostgresStore(nil, nil)
	if _, err := store.issueGrant(
		context.Background(), grant.TenantID, grant.WorkspaceID, grant.ApprovalID, grant,
		GrantSignatureEd25519, strings.Repeat("b", 128), grant.IssuedAt,
	); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("unconfigured verifier error = %v, want ErrGrantSignatureRejected", err)
	}
}

func TestGrantConsumptionSignatureBindsGrantConsumerAndTrustRoot(t *testing.T) {
	_, _, _, grant := ceremonyFixtures(t)
	consumption := consumptionForGrant(t, grant, "spiffe://helm/data-plane-a", grant.IssuedAt.Add(time.Minute))
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	signer := crypto.NewEd25519SignerFromKey(privateKey, "approval-test")
	verifier, err := NewEd25519GrantSignatureVerifier(signer.PublicKeyBytes(), grant.SigningKeyRef, grant.KernelTrustRootID)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignApprovalGrantConsumption(consumption, signer)
	if err != nil {
		t.Fatalf("SignApprovalGrantConsumption() error = %v", err)
	}
	if err := verifier.VerifyGrantConsumptionSignature(consumption, GrantSignatureEd25519, signature); err != nil {
		t.Fatalf("VerifyGrantConsumptionSignature() error = %v", err)
	}

	mutated := consumption
	mutated.ConsumedBy = "spiffe://helm/data-plane-b"
	mutated.ConsumptionHash = ""
	mutated, err = mutated.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyGrantConsumptionSignature(mutated, GrantSignatureEd25519, signature); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("consumer substitution error = %v, want ErrGrantSignatureRejected", err)
	}
}
