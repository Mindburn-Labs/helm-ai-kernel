package approvalceremony

// quantum_posture: conformance tests over classical Ed25519 approval-ceremony
// signatures; no post-quantum claim.

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
	const wantCommitmentPayload = `{"approval_id":"approval-a","challenge_hash":"sha256:7d2b4897904a38bfba678cd30b86da4064e9db7895e5e5b3249c6ede5036db46","challenge_spec_hash":"sha256:217dbb6a38995d8906fd2c9627b53e3bff2b690547700b9d70fcde34d5d8abbe","domain":"HELM/ApprovalCeremonyCommitment/v1","signer_set_hash":"sha256:6666666666666666666666666666666666666666666666666666666666666666","tenant_id":"tenant-a","verified_at":"2026-07-16T12:07:00Z","workspace_id":"workspace-a"}`
	if got := string(commitmentPayload); got != wantCommitmentPayload {
		t.Fatalf("ceremony commitment payload drifted:\n got: %q\nwant: %q", got, wantCommitmentPayload)
	}
	commitment, err := CeremonyCommitment(record)
	if err != nil {
		t.Fatalf("CeremonyCommitment(): %v", err)
	}
	const wantCommitment = "sha256:44a88d0160e0ab9079094a8535e0085af8b0c30e45954cf64e72690da8c826cb"
	if commitment != wantCommitment {
		t.Fatalf("ceremony commitment drifted: got %q, want %q", commitment, wantCommitment)
	}

	signingPayload, err := ApprovalGrantSigningPayload(grant, GrantSignatureEd25519)
	if err != nil {
		t.Fatalf("ApprovalGrantSigningPayload(): %v", err)
	}
	const wantSigningPayload = `{"algorithm":"ed25519","contract_version":"2026-07-15","domain":"HELM/ApprovalGrantSignature/v1","grant_hash":"sha256:5e6079365534888f7fba5dc22579ed51177ad9bf7594943a95784040ea968930","kernel_trust_root_id":"kernel-root-a","signing_key_ref":"kms://helm/approval-a"}`
	if got := string(signingPayload); got != wantSigningPayload {
		t.Fatalf("approval grant signing payload drifted:\n got: %q\nwant: %q", got, wantSigningPayload)
	}

	consumption := consumptionForGrant(t, grant, "spiffe://helm/data-plane-a", grant.IssuedAt.Add(time.Minute))
	consumptionPayload, err := ApprovalGrantConsumptionSigningPayload(consumption, GrantSignatureEd25519)
	if err != nil {
		t.Fatalf("ApprovalGrantConsumptionSigningPayload(): %v", err)
	}
	const wantConsumptionHash = "sha256:7c6ed2d2dad86951c4e0c857a72aa6f4a84e8c3e1b7ac3e1f86d0eb3ab30d416"
	if consumption.ConsumptionHash != wantConsumptionHash {
		t.Fatalf("approval grant consumption hash drifted: got %q, want %q", consumption.ConsumptionHash, wantConsumptionHash)
	}
	const wantConsumptionPayload = `{"algorithm":"ed25519","consumption_hash":"sha256:7c6ed2d2dad86951c4e0c857a72aa6f4a84e8c3e1b7ac3e1f86d0eb3ab30d416","contract_version":"2026-07-16","domain":"HELM/ApprovalGrantConsumptionSignature/v1","kernel_trust_root_id":"kernel-root-a","signing_key_ref":"kms://helm/approval-a"}`
	if got := string(consumptionPayload); got != wantConsumptionPayload {
		t.Fatalf("approval grant consumption signing payload drifted:\n got: %q\nwant: %q", got, wantConsumptionPayload)
	}
	signer := crypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)), "approval-consumption-vector")
	signature, err := SignApprovalGrantConsumption(consumption, signer)
	if err != nil {
		t.Fatal(err)
	}
	const wantConsumptionPublicKey = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
	const wantConsumptionSignature = "924ce5cda6e0804fbf166b1c09df5df9258bc4fa4ea9ced3e054677c0ad6fe2687ca84dad6eb04b31d0c8cafd96d8e98250f3287b528e548fc8e0984694fa601"
	if signer.PublicKey() != wantConsumptionPublicKey || signature != wantConsumptionSignature {
		t.Fatalf("approval grant consumption signature drifted: key=%q signature=%q", signer.PublicKey(), signature)
	}
}
