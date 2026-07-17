package approvalceremony

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestApprovalCeremonyGoldenVectors(t *testing.T) {
	hold, challenge, verified, grant := ceremonyFixtures(t)
	record := withVerified(withChallenge(hold, challenge), verified)

	commitmentPayload, err := ceremonyCommitmentPayload(record)
	if err != nil {
		t.Fatalf("ceremonyCommitmentPayload(): %v", err)
	}
	const wantCommitmentPayload = `{"approval_id":"approval-a","challenge_hash":"sha256:3d7201d17ca0934aa29cbfddcb5198c464006dc81f50b223e0793ff2ba592b16","challenge_spec_hash":"sha256:9f4c5f0d810209bd80041bb6769ce6eb3f93c3e5b28defb54f8eda73c1ff05fa","domain":"HELM/ApprovalCeremonyCommitment/v1","signer_set_hash":"sha256:6666666666666666666666666666666666666666666666666666666666666666","tenant_id":"tenant-a","verified_at":"2026-07-16T12:07:00Z","workspace_id":"workspace-a"}`
	if got := string(commitmentPayload); got != wantCommitmentPayload {
		t.Fatalf("ceremony commitment payload drifted:\n got: %q\nwant: %q", got, wantCommitmentPayload)
	}
	commitment, err := CeremonyCommitment(record)
	if err != nil {
		t.Fatalf("CeremonyCommitment(): %v", err)
	}
	const wantCommitment = "sha256:5725480249fe1f6b64d8e7d67b3fe9ce2d66160d804535885ffe0cc9951e9cbd"
	if commitment != wantCommitment {
		t.Fatalf("ceremony commitment drifted: got %q, want %q", commitment, wantCommitment)
	}

	signingPayload, err := ApprovalGrantSigningPayload(grant, GrantSignatureEd25519)
	if err != nil {
		t.Fatalf("ApprovalGrantSigningPayload(): %v", err)
	}
	const wantSigningPayload = `{"algorithm":"ed25519","contract_version":"2026-07-17","domain":"HELM/ApprovalGrantSignature/v1","grant_hash":"sha256:db94030d6417a6f3f39c96313505be36a98d234813658e74d48503298f5a32e0","kernel_trust_root_id":"kernel-root-a","signing_key_ref":"kms://helm/approval-a"}`
	if got := string(signingPayload); got != wantSigningPayload {
		t.Fatalf("approval grant signing payload drifted:\n got: %q\nwant: %q", got, wantSigningPayload)
	}

	consumption := consumptionForGrant(t, grant, "spiffe://helm/data-plane-a", grant.IssuedAt.Add(time.Minute))
	consumptionPayload, err := ApprovalGrantConsumptionSigningPayload(consumption, GrantSignatureEd25519)
	if err != nil {
		t.Fatalf("ApprovalGrantConsumptionSigningPayload(): %v", err)
	}
	const wantConsumptionHash = "sha256:ee782895b1f4694444a39a8104d0bd9da22f7f9aaf1940fd1e0f0d3bb48b3d4c"
	if consumption.ConsumptionHash != wantConsumptionHash {
		t.Fatalf("approval grant consumption hash drifted: got %q, want %q", consumption.ConsumptionHash, wantConsumptionHash)
	}
	const wantConsumptionPayload = `{"algorithm":"ed25519","consumption_hash":"sha256:ee782895b1f4694444a39a8104d0bd9da22f7f9aaf1940fd1e0f0d3bb48b3d4c","contract_version":"2026-07-17","domain":"HELM/ApprovalGrantConsumptionSignature/v1","kernel_trust_root_id":"kernel-root-a","signing_key_ref":"kms://helm/approval-a"}`
	if got := string(consumptionPayload); got != wantConsumptionPayload {
		t.Fatalf("approval grant consumption signing payload drifted:\n got: %q\nwant: %q", got, wantConsumptionPayload)
	}
	signer := crypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)), "approval-consumption-vector")
	signature, err := SignApprovalGrantConsumption(consumption, signer)
	if err != nil {
		t.Fatal(err)
	}
	const wantConsumptionPublicKey = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
	const wantConsumptionSignature = "dd4dd8deac3be52bfb0b6fa73f8316fa00a2a031341a7acd8cb8d381299c3b7ada8180ac80caeb48cbe6c1a3b283e225b57ca134008d22160a1f9a6b3e28550b"
	if signer.PublicKey() != wantConsumptionPublicKey || signature != wantConsumptionSignature {
		t.Fatalf("approval grant consumption signature drifted: key=%q signature=%q", signer.PublicKey(), signature)
	}
}
