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
	const wantCommitmentPayload = `{"approval_id":"approval-a","challenge_hash":"sha256:94c42967fd1f87fbb767d3c73795e6f598cd9721007903bc06767e5188efc692","challenge_spec_hash":"sha256:9d4d76a8a4e31345b49040badcd56e2a087118615324ae847801859e9d5de9c3","domain":"HELM/ApprovalCeremonyCommitment/v1","signer_set_hash":"sha256:6666666666666666666666666666666666666666666666666666666666666666","tenant_id":"tenant-a","verified_at":"2026-07-16T12:07:00Z","workspace_id":"workspace-a"}`
	if got := string(commitmentPayload); got != wantCommitmentPayload {
		t.Fatalf("ceremony commitment payload drifted:\n got: %q\nwant: %q", got, wantCommitmentPayload)
	}
	commitment, err := CeremonyCommitment(record)
	if err != nil {
		t.Fatalf("CeremonyCommitment(): %v", err)
	}
	const wantCommitment = "sha256:dc0ddc4648fd9791f4c81a439927fc37290e36566771cd4c2b46a31f5f474302"
	if commitment != wantCommitment {
		t.Fatalf("ceremony commitment drifted: got %q, want %q", commitment, wantCommitment)
	}

	signingPayload, err := ApprovalGrantSigningPayload(grant, GrantSignatureEd25519)
	if err != nil {
		t.Fatalf("ApprovalGrantSigningPayload(): %v", err)
	}
	const wantSigningPayload = `{"algorithm":"ed25519","contract_version":"2026-07-17","domain":"HELM/ApprovalGrantSignature/v1","grant_hash":"sha256:bb6dddd2de0a29c72638b48922989e5e255b4eb8abfd20b0d5258821bdd2c1a6","kernel_trust_root_id":"kernel-root-a","signing_key_ref":"kms://helm/approval-a"}`
	if got := string(signingPayload); got != wantSigningPayload {
		t.Fatalf("approval grant signing payload drifted:\n got: %q\nwant: %q", got, wantSigningPayload)
	}

	consumption := consumptionForGrant(t, grant, "spiffe://helm/data-plane-a", grant.IssuedAt.Add(time.Minute))
	consumptionPayload, err := ApprovalGrantConsumptionSigningPayload(consumption, GrantSignatureEd25519)
	if err != nil {
		t.Fatalf("ApprovalGrantConsumptionSigningPayload(): %v", err)
	}
	const wantConsumptionHash = "sha256:d4e5373c20e7df3b2b97a7937e4b9b9c71e8dc8942a2d6908d3e58cca712f04d"
	if consumption.ConsumptionHash != wantConsumptionHash {
		t.Fatalf("approval grant consumption hash drifted: got %q, want %q", consumption.ConsumptionHash, wantConsumptionHash)
	}
	const wantConsumptionPayload = `{"algorithm":"ed25519","consumption_hash":"sha256:d4e5373c20e7df3b2b97a7937e4b9b9c71e8dc8942a2d6908d3e58cca712f04d","contract_version":"2026-07-17","domain":"HELM/ApprovalGrantConsumptionSignature/v1","kernel_trust_root_id":"kernel-root-a","signing_key_ref":"kms://helm/approval-a"}`
	if got := string(consumptionPayload); got != wantConsumptionPayload {
		t.Fatalf("approval grant consumption signing payload drifted:\n got: %q\nwant: %q", got, wantConsumptionPayload)
	}
	signer := crypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)), "approval-consumption-vector")
	signature, err := SignApprovalGrantConsumption(consumption, signer)
	if err != nil {
		t.Fatal(err)
	}
	const wantConsumptionPublicKey = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
	const wantConsumptionSignature = "8486817b0fe12201675d70368facd4efb0429603c9347b13c62b598c275ad83f7204784aa079b727b470dcad074756655e0235c20593b12e6f5e4420741eee06"
	if signer.PublicKey() != wantConsumptionPublicKey || signature != wantConsumptionSignature {
		t.Fatalf("approval grant consumption signature drifted: key=%q signature=%q", signer.PublicKey(), signature)
	}
}
