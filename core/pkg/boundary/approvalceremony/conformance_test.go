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
	const wantCommitmentPayload = `{"approval_id":"approval-a","challenge_hash":"sha256:7d2b4897904a38bfba678cd30b86da4064e9db7895e5e5b3249c6ede5036db46","challenge_spec_hash":"sha256:217dbb6a38995d8906fd2c9627b53e3bff2b690547700b9d70fcde34d5d8abbe","domain":"HELM/ApprovalCeremonyCommitment/v1","signer_set_hash":"sha256:710a2fd98e973f8186d5432f4118048bea8abebc1fac5956ae3487d7269ed134","tenant_id":"tenant-a","verified_at":"2026-07-16T12:07:00Z","workspace_id":"workspace-a"}`
	if got := string(commitmentPayload); got != wantCommitmentPayload {
		t.Fatalf("ceremony commitment payload drifted:\n got: %q\nwant: %q", got, wantCommitmentPayload)
	}
	commitment, err := CeremonyCommitment(record)
	if err != nil {
		t.Fatalf("CeremonyCommitment(): %v", err)
	}
	const wantCommitment = "sha256:656d8a9036d7df049288610c6d574aac8d50b26e6ee3394063d344137a5b6e86"
	if commitment != wantCommitment {
		t.Fatalf("ceremony commitment drifted: got %q, want %q", commitment, wantCommitment)
	}

	signingPayload, err := ApprovalGrantSigningPayload(grant, GrantSignatureEd25519)
	if err != nil {
		t.Fatalf("ApprovalGrantSigningPayload(): %v", err)
	}
	const wantSigningPayload = `{"algorithm":"ed25519","contract_version":"2026-07-15","domain":"HELM/ApprovalGrantSignature/v1","grant_hash":"sha256:0c663297bd1980347e0b501f0451b67c291e67cbb5bb4b26716aead2dbe401cd","kernel_trust_root_id":"kernel-root-a","signing_key_ref":"kms://helm/approval-a"}`
	if got := string(signingPayload); got != wantSigningPayload {
		t.Fatalf("approval grant signing payload drifted:\n got: %q\nwant: %q", got, wantSigningPayload)
	}
}
