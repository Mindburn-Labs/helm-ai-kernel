package generatedspecapprovalceremony

// quantum_posture: approver authority snapshots carry classical Ed25519
// public keys and SHA-256 commitments only; they make no post-quantum claim.

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const (
	AuthoritySnapshotDomainV1 = "HELM/GeneratedSpecApprovalAuthoritySnapshot/v1"
	AuthoritySnapshotSchemaV1 = "generated-spec-approval-authority-snapshot.v1"
)

// AuthoritySnapshot is the transport-safe projection returned by the
// server-side authority registry. Public keys are canonical lowercase hex so
// the snapshot has one deterministic commitment across services.
type AuthoritySnapshot struct {
	Domain                string                 `json:"domain"`
	SchemaVersion         string                 `json:"schema_version"`
	AuthoritySource       string                 `json:"authority_source"`
	AuthorityVersion      string                 `json:"authority_version"`
	AuthoritySnapshotHash string                 `json:"authority_snapshot_hash"`
	Keys                  []AuthoritySnapshotKey `json:"keys"`
}

type AuthoritySnapshotKey struct {
	KeyID        string    `json:"key_id"`
	TenantID     string    `json:"tenant_id"`
	PrincipalID  string    `json:"principal_id"`
	CredentialID string    `json:"credential_id"`
	DeviceID     string    `json:"device_id"`
	PublicKey    string    `json:"public_key"`
	WorkspaceIDs []string  `json:"workspace_ids"`
	Roles        []string  `json:"roles"`
	Actions      []string  `json:"actions"`
	Audiences    []string  `json:"audiences"`
	Enabled      bool      `json:"enabled"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
}

// SealAuthoritySnapshot normalizes set-valued fields, rejects ambiguous keys,
// and commits the exact authority snapshot consumed by quorum verification.
func SealAuthoritySnapshot(snapshot AuthoritySnapshot) (AuthoritySnapshot, error) {
	if snapshot.Domain == "" {
		snapshot.Domain = AuthoritySnapshotDomainV1
	}
	if snapshot.SchemaVersion == "" {
		snapshot.SchemaVersion = AuthoritySnapshotSchemaV1
	}
	if snapshot.Domain != AuthoritySnapshotDomainV1 || snapshot.SchemaVersion != AuthoritySnapshotSchemaV1 ||
		!validToken(snapshot.AuthoritySource) || !validToken(snapshot.AuthorityVersion) ||
		len(snapshot.Keys) == 0 || len(snapshot.Keys) > 256 {
		return AuthoritySnapshot{}, errors.New("generated spec approval authority snapshot metadata is invalid")
	}

	normalized := snapshot
	normalized.AuthoritySnapshotHash = ""
	normalized.Keys = append([]AuthoritySnapshotKey(nil), snapshot.Keys...)
	seen := make(map[string]struct{}, len(normalized.Keys))
	enabled := false
	for index := range normalized.Keys {
		key := &normalized.Keys[index]
		if _, duplicate := seen[key.KeyID]; duplicate {
			return AuthoritySnapshot{}, fmt.Errorf("generated spec approval authority snapshot has duplicate key %q", key.KeyID)
		}
		seen[key.KeyID] = struct{}{}
		key.WorkspaceIDs = normalizeAuthoritySet(key.WorkspaceIDs)
		key.Roles = normalizeAuthoritySet(key.Roles)
		key.Actions = normalizeAuthoritySet(key.Actions)
		key.Audiences = normalizeAuthoritySet(key.Audiences)
		if err := validateAuthoritySnapshotKey(*key); err != nil {
			return AuthoritySnapshot{}, err
		}
		enabled = enabled || key.Enabled
	}
	if !enabled {
		return AuthoritySnapshot{}, errors.New("generated spec approval authority snapshot has no enabled key")
	}
	slices.SortFunc(normalized.Keys, func(left, right AuthoritySnapshotKey) int {
		return strings.Compare(left.KeyID, right.KeyID)
	})
	hash, err := authoritySnapshotHash(normalized)
	if err != nil {
		return AuthoritySnapshot{}, err
	}
	normalized.AuthoritySnapshotHash = hash
	return normalized, nil
}

// TrustStore verifies the snapshot commitment before projecting it into the
// verifier's pinned authority store.
func (snapshot AuthoritySnapshot) TrustStore() (approvalverify.TrustStore, error) {
	sealed, err := SealAuthoritySnapshot(snapshot)
	if err != nil {
		return approvalverify.TrustStore{}, err
	}
	if snapshot.AuthoritySnapshotHash == "" || sealed.AuthoritySnapshotHash != snapshot.AuthoritySnapshotHash {
		return approvalverify.TrustStore{}, errors.New("generated spec approval authority snapshot hash mismatch")
	}
	keys := make(map[string]approvalverify.TrustedApproverKey, len(sealed.Keys))
	for _, key := range sealed.Keys {
		publicKey, _ := hex.DecodeString(key.PublicKey)
		keys[key.KeyID] = approvalverify.TrustedApproverKey{
			KeyID: key.KeyID, TenantID: key.TenantID, PrincipalID: key.PrincipalID,
			CredentialID: key.CredentialID, DeviceID: key.DeviceID,
			PublicKey:    append(ed25519.PublicKey(nil), publicKey...),
			WorkspaceIDs: append([]string(nil), key.WorkspaceIDs...), Roles: append([]string(nil), key.Roles...),
			Actions: append([]string(nil), key.Actions...), Audiences: append([]string(nil), key.Audiences...),
			Enabled: key.Enabled, NotBefore: key.NotBefore, NotAfter: key.NotAfter,
		}
	}
	return approvalverify.TrustStore{
		AuthoritySource: sealed.AuthoritySource, AuthorityVersion: sealed.AuthorityVersion,
		AuthoritySnapshotHash: sealed.AuthoritySnapshotHash, Keys: keys,
	}, nil
}

func authoritySnapshotHash(snapshot AuthoritySnapshot) (string, error) {
	snapshot.AuthoritySnapshotHash = ""
	hash, err := canonicalize.CanonicalHash(snapshot)
	if err != nil {
		return "", fmt.Errorf("canonicalize generated spec approval authority snapshot: %w", err)
	}
	return "sha256:" + hash, nil
}

func validateAuthoritySnapshotKey(key AuthoritySnapshotKey) error {
	for _, value := range []string{key.KeyID, key.TenantID, key.PrincipalID, key.CredentialID, key.DeviceID} {
		if !validToken(value) {
			return errors.New("generated spec approval authority key identity is invalid")
		}
	}
	publicKey, err := hex.DecodeString(key.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || hex.EncodeToString(publicKey) != key.PublicKey {
		return errors.New("generated spec approval authority public key must be canonical lowercase Ed25519 hex")
	}
	if len(key.WorkspaceIDs) == 0 || len(key.Roles) == 0 || len(key.Actions) == 0 || len(key.Audiences) == 0 {
		return errors.New("generated spec approval authority key scope is incomplete")
	}
	for _, set := range [][]string{key.WorkspaceIDs, key.Roles, key.Actions, key.Audiences} {
		for _, value := range set {
			if !validToken(value) {
				return errors.New("generated spec approval authority key scope is invalid")
			}
		}
	}
	if key.NotBefore.IsZero() || key.NotAfter.IsZero() || key.NotBefore.Location() != time.UTC ||
		key.NotAfter.Location() != time.UTC || !key.NotAfter.After(key.NotBefore) {
		return errors.New("generated spec approval authority key lifetime is invalid")
	}
	return nil
}

func normalizeAuthoritySet(values []string) []string {
	values = append([]string(nil), values...)
	slices.Sort(values)
	return slices.Compact(values)
}
