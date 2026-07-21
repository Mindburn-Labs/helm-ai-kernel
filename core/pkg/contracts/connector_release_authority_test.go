package contracts

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestConnectorReleaseAuthorityCertifiedAndRevokedLifecycle(t *testing.T) {
	certified := connectorReleaseAuthorityFixture(t)
	if err := certified.ValidateAt(certified.ValidFrom); err != nil {
		t.Fatalf("ValidateAt(valid_from): %v", err)
	}
	if err := certified.ValidateAt(*certified.ValidUntil); !errors.Is(err, ErrConnectorReleaseAuthorityInactive) {
		t.Fatalf("ValidateAt(valid_until) = %v, want inactive", err)
	}

	revoked := certified
	revoked.RegistryRevision = 2
	revoked.State = ConnectorReleaseAuthorityStateRevoked
	revoked.SignedAt = certified.ValidFrom.Add(time.Minute)
	revoked.ValidFrom = revoked.SignedAt
	revoked.ValidUntil = nil
	revoked.PreviousAuthorityHash = certified.AuthorityHash
	revoked.RevokesAuthorityHash = certified.AuthorityHash
	revoked.AuthorityHash = ""
	sealed, err := revoked.Seal()
	if err != nil {
		t.Fatalf("Seal(revoked): %v", err)
	}
	if err := sealed.ValidateIntegrity(); err != nil {
		t.Fatalf("ValidateIntegrity(revoked): %v", err)
	}
	if err := sealed.ValidateAt(sealed.ValidFrom); !errors.Is(err, ErrConnectorReleaseAuthorityInactive) {
		t.Fatalf("ValidateAt(revoked) = %v, want inactive", err)
	}
}

func TestConnectorReleaseAuthorityRejectsUnsafeBindings(t *testing.T) {
	base := connectorReleaseAuthorityFixture(t)
	tests := map[string]func(*ConnectorReleaseAuthority){
		"zero revision":                func(a *ConnectorReleaseAuthority) { a.RegistryRevision = 0 },
		"overflow revision":            func(a *ConnectorReleaseAuthority) { a.RegistryRevision = ConnectorReleaseAuthorityMaxRevision + 1 },
		"global tenant":                func(a *ConnectorReleaseAuthority) { a.TenantID = "tenant-a" },
		"bad executor":                 func(a *ConnectorReleaseAuthority) { a.ConnectorExecutorKind = "process" },
		"bare binary hash":             func(a *ConnectorReleaseAuthority) { a.ConnectorBinaryHash = strings.Repeat("a", 64) },
		"expired window":               func(a *ConnectorReleaseAuthority) { at := a.ValidFrom; a.ValidUntil = &at },
		"nanosecond signed time":       func(a *ConnectorReleaseAuthority) { a.SignedAt = a.SignedAt.Add(time.Nanosecond) },
		"nanosecond validity time":     func(a *ConnectorReleaseAuthority) { a.ValidFrom = a.ValidFrom.Add(time.Nanosecond) },
		"nanosecond expiry time":       func(a *ConnectorReleaseAuthority) { at := a.ValidUntil.Add(time.Nanosecond); a.ValidUntil = &at },
		"revision without predecessor": func(a *ConnectorReleaseAuthority) { a.RegistryRevision = 2 },
		"revocation without target": func(a *ConnectorReleaseAuthority) {
			a.RegistryRevision = 2
			a.State = ConnectorReleaseAuthorityStateRevoked
			a.ValidUntil = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			got := base
			mutate(&got)
			got.AuthorityHash = ""
			if _, err := got.Seal(); !errors.Is(err, ErrConnectorReleaseAuthorityInvalid) {
				t.Fatalf("Seal() error = %v, want invalid", err)
			}
		})
	}
}

func TestConnectorReleaseAuthorityIntegrityRejectsMutation(t *testing.T) {
	authority := connectorReleaseAuthorityFixture(t)
	authority.CertificationHash = "sha256:" + strings.Repeat("b", 64)
	if err := authority.ValidateIntegrity(); !errors.Is(err, ErrConnectorReleaseAuthorityInvalid) {
		t.Fatalf("ValidateIntegrity() error = %v, want invalid", err)
	}
}

func connectorReleaseAuthorityFixture(t *testing.T) ConnectorReleaseAuthority {
	t.Helper()
	validFrom := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	validUntil := validFrom.Add(24 * time.Hour)
	authority, err := (ConnectorReleaseAuthority{
		SchemaVersion: ConnectorReleaseAuthoritySchemaV1, ContractVersion: ConnectorReleaseAuthorityContractV1,
		AuthorityID: "spiffe://helm/connector-release-authority", SigningKeyRef: "kms://helm/connector-release-authority/key-a",
		Algorithm: ConnectorReleaseAuthorityAlgorithmV1, RegistryRevision: 1,
		ScopeKind:   ConnectorReleaseAuthorityScopeGlobal,
		ConnectorID: "connector-a", ConnectorVersion: "1.0.0", State: ConnectorReleaseAuthorityStateCertified,
		ConnectorExecutorKind: "digital", ConnectorSandboxProfile: "sandbox-pack-lifecycle-v1",
		ConnectorDriftPolicyRef: "policy://connector-drift/v1",
		ConnectorBinaryHash:     "sha256:" + strings.Repeat("a", 64),
		ConnectorSignatureRef:   "sigstore://connector-a/1.0.0", ConnectorSignatureHash: "sha256:" + strings.Repeat("b", 64),
		ConnectorSignerID: "publisher-a", CertificationRef: "cert://connector-a/1.0.0",
		CertificationHash: "sha256:" + strings.Repeat("c", 64), CertificationAuthority: "spiffe://helm/certification-review-authority",
		SignedAt: validFrom.Add(-time.Minute), ValidFrom: validFrom, ValidUntil: &validUntil,
	}).Seal()
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	return authority
}
