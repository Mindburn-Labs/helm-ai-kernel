package saas

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// IsolationAuditor verifies that tenant data doesn't leak across boundaries.
type IsolationAuditor struct {
	clock func() time.Time
}

// NewIsolationAuditor creates a new isolation auditor with real clock.
func NewIsolationAuditor() *IsolationAuditor {
	return &IsolationAuditor{
		clock: func() time.Time { return time.Now().UTC() },
	}
}

// newIsolationAuditorWithClock creates an isolation auditor with injectable clock for testing.
func newIsolationAuditorWithClock(clock func() time.Time) *IsolationAuditor {
	return &IsolationAuditor{
		clock: clock,
	}
}

// Audit checks that all resources for a tenant are properly isolated.
// Takes a set of resource->ownerTenantID mappings and verifies no cross-tenant access.
// A resource is considered a "leak" if its owner does not match the audited tenantID.
func (a *IsolationAuditor) Audit(tenantID string, resources map[string]string) *IsolationAuditResult {
	now := a.clock()
	auditID := generateAuditID(tenantID, now)

	leaks := 0
	ownedCount := 0

	for _, ownerID := range resources {
		if ownerID == tenantID {
			ownedCount++
		} else {
			leaks++
		}
	}

	result := &IsolationAuditResult{
		AuditID:          auditID,
		TenantID:         tenantID,
		Passed:           leaks == 0,
		CrossTenantLeaks: leaks,
		ResourcesAudited: len(resources),
		AuditedAt:        now,
	}

	hash, err := computeAuditContentHash(result)
	if err != nil {
		// Fail-closed: if we can't hash, mark as failed.
		result.Passed = false
		result.ContentHash = "hash-error"
		return result
	}
	result.ContentHash = hash

	return result
}

// generateAuditID creates a deterministic audit ID from tenant ID and timestamp.
func generateAuditID(tenantID string, ts time.Time) string {
	input := fmt.Sprintf("audit:%s:%d", tenantID, ts.UnixNano())
	h := sha256.Sum256([]byte(input))
	return "aud-" + hex.EncodeToString(h[:8])
}

// computeAuditContentHash computes a JCS canonical hash for an audit result.
func computeAuditContentHash(result *IsolationAuditResult) (string, error) {
	saved := result.ContentHash
	result.ContentHash = ""
	defer func() { result.ContentHash = saved }()

	hash, err := canonicalize.CanonicalHash(result)
	if err != nil {
		return "", err
	}
	return hash, nil
}
