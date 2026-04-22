package guardian

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuditLog_TamperEvidence(t *testing.T) {
	log := NewAuditLog()

	// 1. Append valid entries
	entry1, err := log.Append("user:alice", "LOGIN", "system", "success")
	assert.NoError(t, err)
	assert.NotEmpty(t, entry1.Hash)
	assert.Empty(t, entry1.PreviousHash)

	entry2, err := log.Append("user:bob", "EXECUTE", "tool:search", "query=foo")
	assert.NoError(t, err)
	assert.NotEmpty(t, entry2.Hash)
	assert.Equal(t, entry1.Hash, entry2.PreviousHash)

	entry3, err := log.Append("system:kernel", "DECISION", "plan:123", "APPROVED")
	assert.NoError(t, err)
	assert.NotEmpty(t, entry3.Hash)
	assert.Equal(t, entry2.Hash, entry3.PreviousHash)

	// 2. Verify valid chain
	start := time.Now()
	valid, err := log.VerifyChain()
	assert.NoError(t, err)
	assert.True(t, valid, "Chain should be valid")
	t.Logf("Chain verification took %v", time.Since(start))

	// 3. Tamper with middle entry content
	log.Entries[1].Details = "query=malicious_injection"
	// Note: Hash is now invalid for content
	valid, err = log.VerifyChain()
	assert.False(t, valid, "Chain should be invalid after content tampering")
	if err != nil {
		assert.Contains(t, err.Error(), "integrity failure at index 1")
	}

	// 4. Restore content, but break the link
	log.Entries[1].Details = "query=foo"
	log.Entries[2].PreviousHash = "deadbeef"
	valid, err = log.VerifyChain()
	assert.False(t, valid, "Chain should be invalid after link tampering")
	if err != nil {
		assert.Contains(t, err.Error(), "chain broken at index 2")
	}
}
