package contracts

import (
	"errors"
	"testing"
	"time"
)

func TestApprovalGrantSealDeterministicAndBindsAuthorityFields(t *testing.T) {
	base := validApprovalGrant()
	sealed, err := base.Seal()
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	sealedAgain, err := sealed.Seal()
	if err != nil {
		t.Fatalf("Seal() repeat error = %v", err)
	}
	if sealed.GrantHash != sealedAgain.GrantHash {
		t.Fatalf("Seal() is not deterministic: %s != %s", sealed.GrantHash, sealedAgain.GrantHash)
	}

	mutations := map[string]func(*ApprovalGrant){
		"grant id":        func(g *ApprovalGrant) { g.GrantID = "grant-b" },
		"tenant":          func(g *ApprovalGrant) { g.TenantID = "tenant-b" },
		"workspace":       func(g *ApprovalGrant) { g.WorkspaceID = "workspace-b" },
		"audience":        func(g *ApprovalGrant) { g.Audience = "packs.lifecycle.other" },
		"pack":            func(g *ApprovalGrant) { g.PackID = "pack-b" },
		"pack version":    func(g *ApprovalGrant) { g.PackVersion = "2.0.0" },
		"manifest":        func(g *ApprovalGrant) { g.PackManifestHash = sha256Ref("b") },
		"action":          func(g *ApprovalGrant) { g.Action = ApprovalGrantActionUninstall },
		"intent":          func(g *ApprovalGrant) { g.IntentHash = sha256Ref("c") },
		"effect":          func(g *ApprovalGrant) { g.EffectHash = sha256Ref("d") },
		"plan":            func(g *ApprovalGrant) { g.PlanHash = sha256Ref("e") },
		"policy version":  func(g *ApprovalGrant) { g.PolicyVersion = "policy-v2" },
		"policy epoch":    func(g *ApprovalGrant) { g.PolicyEpoch = "epoch-2" },
		"policy hash":     func(g *ApprovalGrant) { g.PolicyHash = sha256Ref("f") },
		"approval":        func(g *ApprovalGrant) { g.ApprovalID = "approval-b" },
		"ceremony":        func(g *ApprovalGrant) { g.CeremonyHash = sha256Ref("1") },
		"signer set":      func(g *ApprovalGrant) { g.SignerSetHash = sha256Ref("2") },
		"server identity": func(g *ApprovalGrant) { g.ServerIdentity = "spiffe://helm/server-b" },
		"trust root":      func(g *ApprovalGrant) { g.KernelTrustRootID = "trust-root-b" },
		"signing key":     func(g *ApprovalGrant) { g.SigningKeyRef = "key-b" },
		"issued at":       func(g *ApprovalGrant) { g.IssuedAt = g.IssuedAt.Add(time.Second) },
		"expires at":      func(g *ApprovalGrant) { g.ExpiresAt = g.ExpiresAt.Add(time.Second) },
		"nonce":           func(g *ApprovalGrant) { g.Nonce = repeatHex("3") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			candidate.ConnectorAuthority = approvalConnectorAuthorityFor(
				candidate.TenantID, candidate.WorkspaceID, candidate.PackID, candidate.PackVersion,
				candidate.PackManifestHash, candidate.Action, candidate.EffectHash, candidate.PolicyHash,
			)
			changed, err := candidate.Seal()
			if err != nil {
				t.Fatalf("Seal() mutated error = %v", err)
			}
			if changed.GrantHash == sealed.GrantHash {
				t.Fatalf("authority mutation did not change grant hash %s", sealed.GrantHash)
			}
		})
	}
}

func TestApprovalGrantValidateRejectsMissingAuthorityFields(t *testing.T) {
	tests := map[string]func(*ApprovalGrant){
		"schema":          func(g *ApprovalGrant) { g.SchemaVersion = "" },
		"contract":        func(g *ApprovalGrant) { g.ContractVersion = "" },
		"grant id":        func(g *ApprovalGrant) { g.GrantID = "" },
		"tenant":          func(g *ApprovalGrant) { g.TenantID = "" },
		"workspace":       func(g *ApprovalGrant) { g.WorkspaceID = "" },
		"audience":        func(g *ApprovalGrant) { g.Audience = "" },
		"pack":            func(g *ApprovalGrant) { g.PackID = "" },
		"pack version":    func(g *ApprovalGrant) { g.PackVersion = "" },
		"pack manifest":   func(g *ApprovalGrant) { g.PackManifestHash = "" },
		"action":          func(g *ApprovalGrant) { g.Action = "" },
		"intent":          func(g *ApprovalGrant) { g.IntentHash = "" },
		"effect":          func(g *ApprovalGrant) { g.EffectHash = "" },
		"plan":            func(g *ApprovalGrant) { g.PlanHash = "" },
		"decision":        func(g *ApprovalGrant) { g.Decision = "" },
		"policy version":  func(g *ApprovalGrant) { g.PolicyVersion = "" },
		"policy epoch":    func(g *ApprovalGrant) { g.PolicyEpoch = "" },
		"policy hash":     func(g *ApprovalGrant) { g.PolicyHash = "" },
		"approval":        func(g *ApprovalGrant) { g.ApprovalID = "" },
		"ceremony":        func(g *ApprovalGrant) { g.CeremonyHash = "" },
		"signer set":      func(g *ApprovalGrant) { g.SignerSetHash = "" },
		"server identity": func(g *ApprovalGrant) { g.ServerIdentity = "" },
		"trust root":      func(g *ApprovalGrant) { g.KernelTrustRootID = "" },
		"signing key":     func(g *ApprovalGrant) { g.SigningKeyRef = "" },
		"issued at":       func(g *ApprovalGrant) { g.IssuedAt = time.Time{} },
		"expires at":      func(g *ApprovalGrant) { g.ExpiresAt = time.Time{} },
		"nonce":           func(g *ApprovalGrant) { g.Nonce = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			grant := validApprovalGrant()
			mutate(&grant)
			if err := grant.Validate(); !errors.Is(err, ErrApprovalGrantInvalid) {
				t.Fatalf("Validate() error = %v, want ErrApprovalGrantInvalid", err)
			}
		})
	}
}

func TestApprovalGrantValidateRejectsMalformedOrUnsafeValues(t *testing.T) {
	tests := map[string]func(*ApprovalGrant){
		"unknown schema":        func(g *ApprovalGrant) { g.SchemaVersion = "approval-grant.v2" },
		"unknown contract":      func(g *ApprovalGrant) { g.ContractVersion = "2099-01-01" },
		"untrimmed tenant":      func(g *ApprovalGrant) { g.TenantID = " tenant-a" },
		"malformed hash":        func(g *ApprovalGrant) { g.IntentHash = "sha256:abc" },
		"uppercase hash":        func(g *ApprovalGrant) { g.EffectHash = "sha256:" + repeatHex("A") },
		"unsupported action":    func(g *ApprovalGrant) { g.Action = "delete" },
		"non-allow decision":    func(g *ApprovalGrant) { g.Decision = "DENY" },
		"expiry equals issue":   func(g *ApprovalGrant) { g.ExpiresAt = g.IssuedAt },
		"expiry before issue":   func(g *ApprovalGrant) { g.ExpiresAt = g.IssuedAt.Add(-time.Second) },
		"short nonce":           func(g *ApprovalGrant) { g.Nonce = "ab" },
		"uppercase nonce":       func(g *ApprovalGrant) { g.Nonce = repeatHex("A") },
		"malformed sealed hash": func(g *ApprovalGrant) { g.GrantHash = "sha256:abc" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			grant := validApprovalGrant()
			mutate(&grant)
			if err := grant.Validate(); !errors.Is(err, ErrApprovalGrantInvalid) {
				t.Fatalf("Validate() error = %v, want ErrApprovalGrantInvalid", err)
			}
		})
	}

	for _, action := range []string{
		ApprovalGrantActionInstall,
		ApprovalGrantActionUpgrade,
		ApprovalGrantActionUninstall,
		ApprovalGrantActionRollback,
	} {
		t.Run("allowed action "+action, func(t *testing.T) {
			grant := validApprovalGrant()
			grant.Action = action
			grant.ConnectorAuthority = approvalConnectorAuthorityFor(
				grant.TenantID, grant.WorkspaceID, grant.PackID, grant.PackVersion,
				grant.PackManifestHash, grant.Action, grant.EffectHash, grant.PolicyHash,
			)
			if err := grant.Validate(); err != nil {
				t.Fatalf("Validate() action %q error = %v", action, err)
			}
		})
	}
}

func TestApprovalGrantValidateAtChecksIntegrityAndWindow(t *testing.T) {
	grant := validApprovalGrant()
	now := grant.IssuedAt.Add(time.Minute)

	if err := grant.ValidateAt(now); !errors.Is(err, ErrApprovalGrantIntegrity) {
		t.Fatalf("ValidateAt() unsealed error = %v, want ErrApprovalGrantIntegrity", err)
	}

	sealed, err := grant.Seal()
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if err := sealed.ValidateAt(sealed.IssuedAt); err != nil {
		t.Fatalf("ValidateAt() issued_at error = %v", err)
	}
	if err := sealed.ValidateAt(sealed.ExpiresAt.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("ValidateAt() before expiry error = %v", err)
	}
	if err := sealed.ValidateAt(sealed.IssuedAt.Add(-time.Nanosecond)); !errors.Is(err, ErrApprovalGrantInactive) {
		t.Fatalf("ValidateAt() before issue error = %v, want ErrApprovalGrantInactive", err)
	}
	if err := sealed.ValidateAt(sealed.ExpiresAt); !errors.Is(err, ErrApprovalGrantInactive) {
		t.Fatalf("ValidateAt() at expiry error = %v, want ErrApprovalGrantInactive", err)
	}

	sealed.TenantID = "tenant-substitution"
	if err := sealed.ValidateAt(now); !errors.Is(err, ErrApprovalGrantInvalid) {
		t.Fatalf("ValidateAt() substituted error = %v, want ErrApprovalGrantInvalid", err)
	}
}

func validApprovalGrant() ApprovalGrant {
	issuedAt := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	return ApprovalGrant{
		SchemaVersion:    ApprovalGrantSchemaV1,
		ContractVersion:  ApprovalGrantContractV1,
		GrantID:          "grant-a",
		TenantID:         "tenant-a",
		WorkspaceID:      "workspace-a",
		Audience:         "packs.lifecycle",
		PackID:           "pack-a",
		PackVersion:      "1.0.0",
		PackManifestHash: sha256Ref("a"),
		Action:           ApprovalGrantActionInstall,
		ConnectorAuthority: approvalConnectorAuthorityFor(
			"tenant-a", "workspace-a", "pack-a", "1.0.0", sha256Ref("a"),
			ApprovalGrantActionInstall, sha256Ref("1"), sha256Ref("3"),
		),
		IntentHash:        sha256Ref("0"),
		EffectHash:        sha256Ref("1"),
		PlanHash:          sha256Ref("2"),
		Decision:          ApprovalGrantDecisionAllow,
		PolicyVersion:     "policy-v1",
		PolicyEpoch:       "epoch-1",
		PolicyHash:        sha256Ref("3"),
		ApprovalID:        "approval-a",
		CeremonyHash:      sha256Ref("4"),
		SignerSetHash:     sha256Ref("5"),
		ServerIdentity:    "spiffe://helm/server-a",
		KernelTrustRootID: "trust-root-a",
		SigningKeyRef:     "key-a",
		IssuedAt:          issuedAt,
		ExpiresAt:         issuedAt.Add(5 * time.Minute),
		Nonce:             repeatHex("6"),
	}
}

func approvalConnectorAuthorityFor(
	tenantID, workspaceID, packID, packVersion, packManifestHash, action, effectHash, policyHash string,
) ApprovalConnectorAuthority {
	authority, err := (ApprovalConnectorAuthority{
		SchemaVersion: ApprovalConnectorAuthoritySchemaV1, ContractVersion: ApprovalConnectorAuthorityContractV1,
		State: ApprovalConnectorAuthorityStateV1, BindingRef: "binding-a",
		TenantID: tenantID, WorkspaceID: workspaceID, PackID: packID, PackVersion: packVersion,
		PackManifestHash: packManifestHash, Action: action, ConnectorAction: action,
		EffectHash: effectHash, PolicyHash: policyHash,
		ConnectorID: "connector-a", ConnectorVersion: "1.0.0",
		ReleaseScopeKind: ConnectorReleaseAuthorityScopeGlobal, ReleaseAuthorityID: "connector-registry-a",
		ReleaseRegistryRevision: 1, ReleaseAuthorityHash: sha256Ref("4"), ConnectorExecutorKind: "digital",
		ConnectorBinaryHash: sha256Ref("7"), ConnectorSignatureRef: "sigstore://connector-a/1.0.0",
		ConnectorSignatureHash: sha256Ref("6"),
		ConnectorSignerID:      "publisher-a", ConnectorSandboxProfile: "sandbox-pack-lifecycle-v1",
		ConnectorDriftPolicyRef: "policy://connector-drift/v1", CertificationRef: "cert://connector-a/1.0.0",
		CertificationHash: sha256Ref("8"), CertificationAuthority: "spiffe://helm/certification-authority",
	}).Seal()
	if err != nil {
		panic(err)
	}
	return authority
}

func sha256Ref(character string) string {
	return "sha256:" + repeatHex(character)
}

func repeatHex(character string) string {
	result := ""
	for len(result) < 64 {
		result += character
	}
	return result
}
