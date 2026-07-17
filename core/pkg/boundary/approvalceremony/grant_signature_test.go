package approvalceremony

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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

func TestDispatchAdmissionSignatureBindsAttemptConnectorAndTrustRoot(t *testing.T) {
	_, _, _, grant := ceremonyFixtures(t)
	consumption := consumptionForGrant(t, grant, "spiffe://helm/data-plane-a", grant.IssuedAt.Add(time.Minute))
	issuedAt := consumption.ConsumedAt.Add(time.Second)
	admission, err := (contracts.ApprovalDispatchAdmission{
		SchemaVersion:   contracts.ApprovalDispatchAdmissionSchemaV1,
		ContractVersion: contracts.ApprovalDispatchAdmissionContractV1,
		Coverage:        contracts.ApprovalDispatchAdmissionCoverageV1,
		AdmissionID:     "dispatch-admission-a", AttemptID: "attempt-a", State: contracts.ApprovalDispatchAdmissionStateV1,
		ApprovalID: consumption.ApprovalID, GrantID: consumption.GrantID,
		GrantHash: consumption.GrantHash, ConsumptionHash: consumption.ConsumptionHash,
		TenantID: consumption.TenantID, WorkspaceID: consumption.WorkspaceID,
		Audience: consumption.Audience, AdmittedBy: consumption.ConsumedBy,
		IdempotencyKeyHash: "sha256:" + strings.Repeat("a", 64), EffectHash: consumption.EffectHash,
		ConnectorID: "connector-a", Action: consumption.Action,
		KernelTrustRootID: consumption.KernelTrustRootID, SigningKeyRef: consumption.SigningKeyRef,
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(30 * time.Second),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{13}, ed25519.SeedSize))
	signer := crypto.NewEd25519SignerFromKey(privateKey, "dispatch-signature-test")
	verifier, err := NewEd25519GrantSignatureVerifier(
		signer.PublicKeyBytes(), admission.SigningKeyRef, admission.KernelTrustRootID,
	)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignApprovalDispatchAdmission(admission, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyDispatchAdmissionSignature(admission, GrantSignatureEd25519, signature); err != nil {
		t.Fatalf("VerifyDispatchAdmissionSignature(): %v", err)
	}
	payloadA, err := ApprovalDispatchAdmissionSigningPayload(admission, GrantSignatureEd25519)
	if err != nil {
		t.Fatal(err)
	}
	payloadB, err := ApprovalDispatchAdmissionSigningPayload(admission, GrantSignatureEd25519)
	if err != nil || !bytes.Equal(payloadA, payloadB) {
		t.Fatalf("dispatch admission signing payload is not deterministic: %v", err)
	}
	mutated := admission
	mutated.ConnectorID = "connector-b"
	mutated.AdmissionHash = ""
	mutated, err = mutated.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyDispatchAdmissionSignature(mutated, GrantSignatureEd25519, signature); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("connector substitution error = %v, want ErrGrantSignatureRejected", err)
	}
	mutated = admission
	mutated.SigningKeyRef = "kernel-key-other"
	mutated.AdmissionHash = ""
	mutated, err = mutated.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyDispatchAdmissionSignature(mutated, GrantSignatureEd25519, signature); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("trust-root metadata substitution error = %v, want ErrGrantSignatureRejected", err)
	}
	consumptionSignature, err := SignApprovalGrantConsumption(consumption, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyDispatchAdmissionSignature(admission, GrantSignatureEd25519, consumptionSignature); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("cross-domain signature error = %v, want ErrGrantSignatureRejected", err)
	}
}
