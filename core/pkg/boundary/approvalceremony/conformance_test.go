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
	const wantCommitmentPayload = `{"approval_id":"approval-a","challenge_hash":"sha256:a8b4bc414c78408e017dfdfe5211ad8e07052659a27bba2a68be024abeb6bfb3","challenge_spec_hash":"sha256:22974cb9315f6e25b55e3a07457d2ac9318a619f13c1898f3eedbc6cf1c72995","domain":"HELM/ApprovalCeremonyCommitment/v1","signer_set_hash":"sha256:6666666666666666666666666666666666666666666666666666666666666666","tenant_id":"tenant-a","verified_at":"2026-07-16T12:07:00Z","workspace_id":"workspace-a"}`
	if got := string(commitmentPayload); got != wantCommitmentPayload {
		t.Fatalf("ceremony commitment payload drifted:\n got: %q\nwant: %q", got, wantCommitmentPayload)
	}
	commitment, err := CeremonyCommitment(record)
	if err != nil {
		t.Fatalf("CeremonyCommitment(): %v", err)
	}
	const wantCommitment = "sha256:462cdab3849d3602e1fcb81b7325aee15e765efeb4a9ecee356f1f034d256e23"
	if commitment != wantCommitment {
		t.Fatalf("ceremony commitment drifted: got %q, want %q", commitment, wantCommitment)
	}

	signingPayload, err := ApprovalGrantSigningPayload(grant, GrantSignatureEd25519)
	if err != nil {
		t.Fatalf("ApprovalGrantSigningPayload(): %v", err)
	}
	const wantSigningPayload = `{"algorithm":"ed25519","contract_version":"2026-07-17","domain":"HELM/ApprovalGrantSignature/v1","grant_hash":"sha256:397146f61b94d654cdf666be96c5d9cd408cfd60ad725a8741fb4c92f744ba02","kernel_trust_root_id":"kernel-root-a","signing_key_ref":"kms://helm/approval-a"}`
	if got := string(signingPayload); got != wantSigningPayload {
		t.Fatalf("approval grant signing payload drifted:\n got: %q\nwant: %q", got, wantSigningPayload)
	}

	consumption := consumptionForGrant(t, grant, "spiffe://helm/data-plane-a", grant.IssuedAt.Add(time.Minute))
	consumptionPayload, err := ApprovalGrantConsumptionSigningPayload(consumption, GrantSignatureEd25519)
	if err != nil {
		t.Fatalf("ApprovalGrantConsumptionSigningPayload(): %v", err)
	}
	const wantConsumptionHash = "sha256:9f9b155c9794acafc03cc66e4e24274fd7a6f28e43cba0c0e9a3f500df0c5d56"
	if consumption.ConsumptionHash != wantConsumptionHash {
		t.Fatalf("approval grant consumption hash drifted: got %q, want %q", consumption.ConsumptionHash, wantConsumptionHash)
	}
	const wantConsumptionPayload = `{"algorithm":"ed25519","consumption_hash":"sha256:9f9b155c9794acafc03cc66e4e24274fd7a6f28e43cba0c0e9a3f500df0c5d56","contract_version":"2026-07-17","domain":"HELM/ApprovalGrantConsumptionSignature/v1","kernel_trust_root_id":"kernel-root-a","signing_key_ref":"kms://helm/approval-a"}`
	if got := string(consumptionPayload); got != wantConsumptionPayload {
		t.Fatalf("approval grant consumption signing payload drifted:\n got: %q\nwant: %q", got, wantConsumptionPayload)
	}
	signer := crypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)), "approval-consumption-vector")
	signature, err := SignApprovalGrantConsumption(consumption, signer)
	if err != nil {
		t.Fatal(err)
	}
	const wantConsumptionPublicKey = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
	const wantConsumptionSignature = "16a0da2ae2f10673518819f10b0b1d6de3375ade0ea00b1e58795126a55a694af09bd18f2f0ecd45d85716f138a9229a381f634a8a4d829b5691a28ea072ca0f"
	if signer.PublicKey() != wantConsumptionPublicKey || signature != wantConsumptionSignature {
		t.Fatalf("approval grant consumption signature drifted: key=%q signature=%q", signer.PublicKey(), signature)
	}
}
