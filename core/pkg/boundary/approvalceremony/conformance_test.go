package approvalceremony

import (
	"testing"
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
}
