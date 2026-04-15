package identity

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cdmFixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestCDM_Grant(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	m := NewContinuousDelegationManager(WithCDMClock(cdmFixedClock(now)))

	d, err := m.Grant("user-1", "agent-1", []string{"file_read", "db_query"}, 10*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, d)

	assert.NotEmpty(t, d.ID)
	assert.Equal(t, "user-1", d.GrantorID)
	assert.Equal(t, "agent-1", d.GranteeID)
	assert.Equal(t, []string{"file_read", "db_query"}, d.Scope)
	assert.Equal(t, 10*time.Minute, d.TTL)
	assert.Equal(t, now, d.GrantedAt)
	assert.Equal(t, now, d.RefreshedAt)
	assert.Nil(t, d.RevokedAt)
	assert.Empty(t, d.ParentID)
}

func TestCDM_GrantValidation(t *testing.T) {
	m := NewContinuousDelegationManager()

	t.Run("empty grantor", func(t *testing.T) {
		_, err := m.Grant("", "agent", []string{"tool"}, time.Minute)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "grantor ID")
	})

	t.Run("empty grantee", func(t *testing.T) {
		_, err := m.Grant("user", "", []string{"tool"}, time.Minute)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "grantee ID")
	})

	t.Run("empty scope", func(t *testing.T) {
		_, err := m.Grant("user", "agent", []string{}, time.Minute)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scope")
	})

	t.Run("zero TTL", func(t *testing.T) {
		_, err := m.Grant("user", "agent", []string{"tool"}, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TTL")
	})

	t.Run("negative TTL", func(t *testing.T) {
		_, err := m.Grant("user", "agent", []string{"tool"}, -time.Minute)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TTL")
	})
}

func TestCDM_RefreshExtendsTTL(t *testing.T) {
	start := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	current := start
	clock := func() time.Time { return current }
	m := NewContinuousDelegationManager(WithCDMClock(clock))

	d, err := m.Grant("user-1", "agent-1", []string{"tool"}, 10*time.Minute)
	require.NoError(t, err)

	// Advance 5 minutes — still active.
	current = start.Add(5 * time.Minute)
	assert.True(t, m.IsActive(d.ID))

	// Refresh.
	err = m.Refresh(d.ID)
	require.NoError(t, err)

	// Advance another 8 minutes (13 min from start) — would have expired
	// without refresh, but still active because refresh reset the window.
	current = start.Add(13 * time.Minute)
	assert.True(t, m.IsActive(d.ID), "should be active after refresh")

	// Advance past refreshed TTL (5+10=15 min from refresh point).
	current = start.Add(16 * time.Minute)
	assert.False(t, m.IsActive(d.ID), "should have expired")
}

func TestCDM_ExpirationDetection(t *testing.T) {
	start := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	current := start
	clock := func() time.Time { return current }
	m := NewContinuousDelegationManager(WithCDMClock(clock))

	d, err := m.Grant("user-1", "agent-1", []string{"tool"}, 5*time.Minute)
	require.NoError(t, err)

	// Active immediately.
	assert.True(t, m.IsActive(d.ID))

	// Still active at boundary.
	current = start.Add(4*time.Minute + 59*time.Second)
	assert.True(t, m.IsActive(d.ID))

	// Expired after TTL.
	current = start.Add(5*time.Minute + time.Second)
	assert.False(t, m.IsActive(d.ID))
}

func TestCDM_Revocation(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	m := NewContinuousDelegationManager(WithCDMClock(cdmFixedClock(now)))

	d, err := m.Grant("user-1", "agent-1", []string{"tool"}, 10*time.Minute)
	require.NoError(t, err)

	assert.True(t, m.IsActive(d.ID))

	err = m.Revoke(d.ID)
	require.NoError(t, err)

	assert.False(t, m.IsActive(d.ID), "revoked delegation should be inactive")
}

func TestCDM_RevokeNotFound(t *testing.T) {
	m := NewContinuousDelegationManager()

	err := m.Revoke("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCDM_RefreshExpired(t *testing.T) {
	start := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	current := start
	clock := func() time.Time { return current }
	m := NewContinuousDelegationManager(WithCDMClock(clock))

	d, err := m.Grant("user-1", "agent-1", []string{"tool"}, 5*time.Minute)
	require.NoError(t, err)

	// Advance past expiry.
	current = start.Add(10 * time.Minute)

	err = m.Refresh(d.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestCDM_RefreshRevoked(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	m := NewContinuousDelegationManager(WithCDMClock(cdmFixedClock(now)))

	d, err := m.Grant("user-1", "agent-1", []string{"tool"}, 10*time.Minute)
	require.NoError(t, err)

	err = m.Revoke(d.ID)
	require.NoError(t, err)

	err = m.Refresh(d.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestCDM_SubDelegateNarrowedScope(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	m := NewContinuousDelegationManager(WithCDMClock(cdmFixedClock(now)))

	parent, err := m.Grant("user-1", "agent-1",
		[]string{"file_read", "file_write", "db_query"}, 30*time.Minute)
	require.NoError(t, err)

	// Narrowed sub-delegation — should succeed.
	child, err := m.SubDelegate(parent.ID, "agent-2", []string{"file_read"})
	require.NoError(t, err)
	require.NotNil(t, child)

	assert.Equal(t, "agent-1", child.GrantorID, "grantor should be parent's grantee")
	assert.Equal(t, "agent-2", child.GranteeID)
	assert.Equal(t, []string{"file_read"}, child.Scope)
	assert.Equal(t, parent.ID, child.ParentID)
	assert.True(t, m.IsActive(child.ID))
}

func TestCDM_SubDelegateScopeWideningRejected(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	m := NewContinuousDelegationManager(WithCDMClock(cdmFixedClock(now)))

	parent, err := m.Grant("user-1", "agent-1", []string{"file_read"}, 30*time.Minute)
	require.NoError(t, err)

	_, err = m.SubDelegate(parent.ID, "agent-2", []string{"file_read", "file_delete"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope widening")
	assert.Contains(t, err.Error(), "file_delete")
}

func TestCDM_CascadeRevocation(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	m := NewContinuousDelegationManager(WithCDMClock(cdmFixedClock(now)))

	// Create a chain: root -> child1 -> grandchild1
	//                      -> child2
	root, err := m.Grant("user-1", "agent-1",
		[]string{"file_read", "file_write", "db_query"}, 60*time.Minute)
	require.NoError(t, err)

	child1, err := m.SubDelegate(root.ID, "agent-2", []string{"file_read", "file_write"})
	require.NoError(t, err)

	child2, err := m.SubDelegate(root.ID, "agent-3", []string{"db_query"})
	require.NoError(t, err)

	grandchild1, err := m.SubDelegate(child1.ID, "agent-4", []string{"file_read"})
	require.NoError(t, err)

	// All should be active.
	assert.True(t, m.IsActive(root.ID))
	assert.True(t, m.IsActive(child1.ID))
	assert.True(t, m.IsActive(child2.ID))
	assert.True(t, m.IsActive(grandchild1.ID))

	// Cascade revoke from root.
	count := m.RevokeWithCascade(root.ID)
	assert.Equal(t, 4, count, "should revoke root + 2 children + 1 grandchild")

	// All should be inactive.
	assert.False(t, m.IsActive(root.ID))
	assert.False(t, m.IsActive(child1.ID))
	assert.False(t, m.IsActive(child2.ID))
	assert.False(t, m.IsActive(grandchild1.ID))
}

func TestCDM_CascadeRevocationPartialChain(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	m := NewContinuousDelegationManager(WithCDMClock(cdmFixedClock(now)))

	root, err := m.Grant("user-1", "agent-1",
		[]string{"file_read", "file_write"}, 60*time.Minute)
	require.NoError(t, err)

	child, err := m.SubDelegate(root.ID, "agent-2", []string{"file_read"})
	require.NoError(t, err)

	grandchild, err := m.SubDelegate(child.ID, "agent-3", []string{"file_read"})
	require.NoError(t, err)

	// Cascade revoke from child only — root should remain active.
	count := m.RevokeWithCascade(child.ID)
	assert.Equal(t, 2, count, "should revoke child + grandchild")

	assert.True(t, m.IsActive(root.ID), "root should still be active")
	assert.False(t, m.IsActive(child.ID))
	assert.False(t, m.IsActive(grandchild.ID))
}

func TestCDM_IsActiveNotFound(t *testing.T) {
	m := NewContinuousDelegationManager()
	assert.False(t, m.IsActive("nonexistent"))
}

func TestCDM_SubDelegateRevokedParent(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	m := NewContinuousDelegationManager(WithCDMClock(cdmFixedClock(now)))

	parent, err := m.Grant("user-1", "agent-1", []string{"tool"}, 30*time.Minute)
	require.NoError(t, err)

	err = m.Revoke(parent.ID)
	require.NoError(t, err)

	_, err = m.SubDelegate(parent.ID, "agent-2", []string{"tool"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestCDM_SubDelegateExpiredParent(t *testing.T) {
	start := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	current := start
	clock := func() time.Time { return current }
	m := NewContinuousDelegationManager(WithCDMClock(clock))

	parent, err := m.Grant("user-1", "agent-1", []string{"tool"}, 5*time.Minute)
	require.NoError(t, err)

	current = start.Add(10 * time.Minute)

	_, err = m.SubDelegate(parent.ID, "agent-2", []string{"tool"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestCDM_ConcurrentAccess(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	m := NewContinuousDelegationManager(WithCDMClock(cdmFixedClock(now)))

	// Create a root delegation for sub-delegation tests.
	root, err := m.Grant("user-1", "agent-root", []string{"tool_a", "tool_b"}, time.Hour)
	require.NoError(t, err)

	var wg sync.WaitGroup

	// Concurrent grants.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = m.Grant("user-1", "concurrent-agent", []string{"tool_a"}, 10*time.Minute)
		}()
	}

	// Concurrent sub-delegations.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = m.SubDelegate(root.ID, "sub-agent", []string{"tool_a"})
		}()
	}

	// Concurrent IsActive checks.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.IsActive(root.ID)
		}()
	}

	wg.Wait()

	// No panics — state is consistent.
	assert.True(t, m.IsActive(root.ID))
}

func TestCDM_GrantReturnsCopy(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	m := NewContinuousDelegationManager(WithCDMClock(cdmFixedClock(now)))

	d, err := m.Grant("user-1", "agent-1", []string{"tool_a"}, 10*time.Minute)
	require.NoError(t, err)

	// Mutate returned scope.
	d.Scope[0] = "TAMPERED"

	// Internal state should be unaffected.
	assert.True(t, m.IsActive(d.ID))
}
