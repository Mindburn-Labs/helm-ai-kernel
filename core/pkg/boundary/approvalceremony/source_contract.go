package approvalceremony

// quantum_posture: approver authority snapshots carry classical Ed25519
// public keys and SHA-256 commitments only; they make no post-quantum claim.

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"

const (
	AuthoritySnapshotDomainV1 = "HELM/ApprovalAuthoritySnapshot/v1"
	AuthoritySnapshotSchemaV1 = "approval-authority-snapshot.v1"
)

type AuthoritySnapshot approvalverify.AuthoritySnapshot
type AuthoritySnapshotKey = approvalverify.AuthoritySnapshotKey

var authoritySnapshotProfile = approvalverify.AuthoritySnapshotProfile{
	Domain: AuthoritySnapshotDomainV1, SchemaVersion: AuthoritySnapshotSchemaV1,
}

func SealAuthoritySnapshot(snapshot AuthoritySnapshot) (AuthoritySnapshot, error) {
	sealed, err := approvalverify.SealAuthoritySnapshot(approvalverify.AuthoritySnapshot(snapshot), authoritySnapshotProfile)
	return AuthoritySnapshot(sealed), err
}

func (snapshot AuthoritySnapshot) TrustStore() (approvalverify.TrustStore, error) {
	return approvalverify.AuthoritySnapshotTrustStore(approvalverify.AuthoritySnapshot(snapshot), authoritySnapshotProfile)
}
