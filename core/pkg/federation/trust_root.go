package federation

import (
	"fmt"
	"sort"
	"sync"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// TrustRootStore manages cross-org trust roots.
// All operations are thread-safe.
type TrustRootStore struct {
	mu    sync.RWMutex
	roots map[string]*OrgTrustRoot // orgID -> trust root
}

// NewTrustRootStore creates an empty trust root store.
func NewTrustRootStore() *TrustRootStore {
	return &TrustRootStore{
		roots: make(map[string]*OrgTrustRoot),
	}
}

// Register adds a new organization trust root to the store.
// Returns an error if the org ID is empty, the public key is empty,
// or an org with the same ID is already registered (and not revoked).
func (s *TrustRootStore) Register(root OrgTrustRoot) error {
	if root.OrgID == "" {
		return fmt.Errorf("federation: org_id must not be empty")
	}
	if root.PublicKey == "" {
		return fmt.Errorf("federation: public_key must not be empty for org %s", root.OrgID)
	}

	// Compute content hash via JCS canonicalization.
	hash, err := computeOrgTrustRootHash(&root)
	if err != nil {
		return fmt.Errorf("federation: content hash failed for org %s: %w", root.OrgID, err)
	}
	root.ContentHash = hash

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.roots[root.OrgID]; ok && !existing.Revoked {
		return fmt.Errorf("federation: org %s is already registered", root.OrgID)
	}

	copied := root
	s.roots[root.OrgID] = &copied
	return nil
}

// Revoke marks an organization's trust root as revoked.
// Returns an error if the org is not found.
func (s *TrustRootStore) Revoke(orgID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	root, ok := s.roots[orgID]
	if !ok {
		return fmt.Errorf("federation: org %s not found", orgID)
	}
	root.Revoked = true
	return nil
}

// Get returns the trust root for a given org ID.
// The second return value is false if the org is not found.
func (s *TrustRootStore) Get(orgID string) (*OrgTrustRoot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	root, ok := s.roots[orgID]
	if !ok {
		return nil, false
	}
	copied := *root
	return &copied, true
}

// IsTrusted returns true if the org is registered and not revoked.
func (s *TrustRootStore) IsTrusted(orgID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	root, ok := s.roots[orgID]
	return ok && !root.Revoked
}

// ListTrusted returns all non-revoked trust roots, sorted by OrgID.
func (s *TrustRootStore) ListTrusted() []OrgTrustRoot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var trusted []OrgTrustRoot
	for _, root := range s.roots {
		if !root.Revoked {
			trusted = append(trusted, *root)
		}
	}
	sort.Slice(trusted, func(i, j int) bool {
		return trusted[i].OrgID < trusted[j].OrgID
	})
	return trusted
}

// computeOrgTrustRootHash computes a JCS + SHA-256 content hash for an OrgTrustRoot.
// The hash excludes the ContentHash and Revoked fields to produce a stable identity.
func computeOrgTrustRootHash(root *OrgTrustRoot) (string, error) {
	hashable := struct {
		OrgID         string `json:"org_id"`
		OrgDID        string `json:"org_did"`
		OrgName       string `json:"org_name"`
		PublicKey     string `json:"public_key"`
		Algorithm     string `json:"algorithm"`
		EstablishedAt string `json:"established_at"`
	}{
		OrgID:         root.OrgID,
		OrgDID:        root.OrgDID,
		OrgName:       root.OrgName,
		PublicKey:     root.PublicKey,
		Algorithm:     root.Algorithm,
		EstablishedAt: root.EstablishedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	return canonicalize.CanonicalHash(hashable)
}
