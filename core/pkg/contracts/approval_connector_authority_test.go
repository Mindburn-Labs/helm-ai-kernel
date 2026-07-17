package contracts

import (
	"errors"
	"testing"
	"time"
)

func TestApprovalConnectorAuthoritySealsExactEffectAndRelease(t *testing.T) {
	authority := approvalConnectorAuthorityFor(
		"tenant-a", "workspace-a", "pack-a", "1.0.0", sha256Ref("a"),
		ApprovalGrantActionInstall, sha256Ref("1"), sha256Ref("3"),
	)
	if err := authority.ValidateEffectBinding(
		"tenant-a", "workspace-a", "pack-a", "1.0.0", sha256Ref("a"),
		ApprovalGrantActionInstall, sha256Ref("1"), sha256Ref("3"),
	); err != nil {
		t.Fatalf("ValidateEffectBinding(): %v", err)
	}
	sealedAgain, err := authority.Seal()
	if err != nil || sealedAgain.AuthorityHash != authority.AuthorityHash {
		t.Fatalf("deterministic Seal() = %+v, %v", sealedAgain, err)
	}

	mutated := authority
	mutated.ConnectorBinaryHash = sha256Ref("9")
	if err := mutated.ValidateIntegrity(); !errors.Is(err, ErrApprovalGrantIntegrity) {
		t.Fatalf("binary substitution error = %v, want integrity failure", err)
	}
	if err := authority.ValidateEffectBinding(
		"tenant-a", "workspace-a", "pack-a", "1.0.0", sha256Ref("a"),
		ApprovalGrantActionRollback, sha256Ref("1"), sha256Ref("3"),
	); !errors.Is(err, ErrApprovalGrantIntegrity) {
		t.Fatalf("effect substitution error = %v, want integrity failure", err)
	}
}

func TestApprovalConnectorAuthorityRejectsUncertifiedOrIncompleteRelease(t *testing.T) {
	base := approvalConnectorAuthorityFor(
		"tenant-a", "workspace-a", "pack-a", "1.0.0", sha256Ref("a"),
		ApprovalGrantActionInstall, sha256Ref("1"), sha256Ref("3"),
	)
	tests := map[string]func(*ApprovalConnectorAuthority){
		"candidate state":       func(a *ApprovalConnectorAuthority) { a.State = "candidate" },
		"missing release scope": func(a *ApprovalConnectorAuthority) { a.ReleaseScopeKind = "" },
		"missing authority id":  func(a *ApprovalConnectorAuthority) { a.ReleaseAuthorityID = "" },
		"zero registry revision": func(a *ApprovalConnectorAuthority) {
			a.ReleaseRegistryRevision = 0
		},
		"bad authority hash": func(a *ApprovalConnectorAuthority) { a.ReleaseAuthorityHash = "sha256:no" },
		"missing signature":  func(a *ApprovalConnectorAuthority) { a.ConnectorSignatureRef = "" },
		"bad signature hash": func(a *ApprovalConnectorAuthority) { a.ConnectorSignatureHash = "sha256:no" },
		"missing signer":     func(a *ApprovalConnectorAuthority) { a.ConnectorSignerID = "" },
		"missing cert":       func(a *ApprovalConnectorAuthority) { a.CertificationRef = "" },
		"bad cert hash":      func(a *ApprovalConnectorAuthority) { a.CertificationHash = "sha256:no" },
		"bad executor":       func(a *ApprovalConnectorAuthority) { a.ConnectorExecutorKind = "kinetic" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.AuthorityHash = ""
			mutate(&candidate)
			if _, err := candidate.Seal(); !errors.Is(err, ErrApprovalGrantIntegrity) {
				t.Fatalf("Seal() error = %v, want integrity failure", err)
			}
		})
	}
}

func TestApprovalConnectorAuthorityMatchesExactCurrentRelease(t *testing.T) {
	approval := approvalConnectorAuthorityFor(
		"tenant-a", "workspace-a", "pack-a", "1.0.0", sha256Ref("a"),
		ApprovalGrantActionInstall, sha256Ref("1"), sha256Ref("3"),
	)
	validUntil := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	release, err := (ConnectorReleaseAuthority{
		SchemaVersion: ConnectorReleaseAuthoritySchemaV1, ContractVersion: ConnectorReleaseAuthorityContractV1,
		AuthorityID: approval.ReleaseAuthorityID, SigningKeyRef: "release-key-a",
		Algorithm: ConnectorReleaseAuthorityAlgorithmV1, RegistryRevision: approval.ReleaseRegistryRevision,
		ScopeKind: approval.ReleaseScopeKind, ConnectorID: approval.ConnectorID, ConnectorVersion: approval.ConnectorVersion,
		State: ConnectorReleaseAuthorityStateCertified, ConnectorExecutorKind: approval.ConnectorExecutorKind,
		ConnectorSandboxProfile: approval.ConnectorSandboxProfile, ConnectorDriftPolicyRef: approval.ConnectorDriftPolicyRef,
		ConnectorBinaryHash: approval.ConnectorBinaryHash, ConnectorSignatureRef: approval.ConnectorSignatureRef,
		ConnectorSignatureHash: approval.ConnectorSignatureHash, ConnectorSignerID: approval.ConnectorSignerID,
		CertificationRef: approval.CertificationRef, CertificationHash: approval.CertificationHash,
		CertificationAuthority: approval.CertificationAuthority,
		SignedAt:               time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
		ValidFrom:              time.Date(2026, 7, 17, 12, 0, 1, 0, time.UTC), ValidUntil: &validUntil,
	}).Seal()
	if err != nil {
		t.Fatalf("seal release authority: %v", err)
	}
	approval.ReleaseAuthorityHash = release.AuthorityHash
	approval.AuthorityHash = ""
	approval, err = approval.Seal()
	if err != nil {
		t.Fatalf("seal approval authority: %v", err)
	}
	if err := approval.ValidateCurrentRelease(release); err != nil {
		t.Fatalf("ValidateCurrentRelease(): %v", err)
	}

	mismatch := approval
	mismatch.ReleaseRegistryRevision++
	mismatch.AuthorityHash = ""
	mismatch, err = mismatch.Seal()
	if err != nil {
		t.Fatalf("seal mismatched approval authority: %v", err)
	}
	if err := mismatch.ValidateCurrentRelease(release); !errors.Is(err, ErrApprovalGrantIntegrity) {
		t.Fatalf("revision mismatch error = %v, want integrity failure", err)
	}
}
