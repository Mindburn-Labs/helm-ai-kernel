package contracts

import (
	"errors"
	"testing"
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
		"candidate state":   func(a *ApprovalConnectorAuthority) { a.State = "candidate" },
		"missing signature": func(a *ApprovalConnectorAuthority) { a.ConnectorSignatureRef = "" },
		"missing signer":    func(a *ApprovalConnectorAuthority) { a.ConnectorSignerID = "" },
		"missing cert":      func(a *ApprovalConnectorAuthority) { a.CertificationRef = "" },
		"bad cert hash":     func(a *ApprovalConnectorAuthority) { a.CertificationHash = "sha256:no" },
		"bad executor":      func(a *ApprovalConnectorAuthority) { a.ConnectorExecutorKind = "kinetic" },
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
