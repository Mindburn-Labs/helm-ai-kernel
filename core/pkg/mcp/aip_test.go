package mcp

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func aipFixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestAIPVerifier_RegisterDelegation(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	v := NewAIPVerifier(WithAIPClock(aipFixedClock(now)))

	err := v.RegisterDelegation(DelegationClaim{
		DelegatorID: "user-1",
		DelegateID:  "agent-1",
		Scope:       []string{"file_read", "file_write"},
		ExpiresAt:   now.Add(time.Hour),
		Signature:   "sig-fixture",
	})
	require.NoError(t, err)

	chain := v.GetChain("agent-1")
	require.Len(t, chain, 1)
	assert.Equal(t, "user-1", chain[0].DelegatorID)
	assert.Equal(t, "agent-1", chain[0].DelegateID)
	assert.Equal(t, []string{"file_read", "file_write"}, chain[0].Scope)
}

func TestAIPVerifier_VerifyAuthorityAllowed(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	v := NewAIPVerifier(WithAIPClock(aipFixedClock(now)))

	err := v.RegisterDelegation(DelegationClaim{
		DelegatorID: "user-1",
		DelegateID:  "agent-1",
		Scope:       []string{"file_read", "file_write"},
		ExpiresAt:   now.Add(time.Hour),
	})
	require.NoError(t, err)

	ok, err := v.VerifyAuthority("agent-1", "file_read")
	require.NoError(t, err)
	assert.True(t, ok, "agent-1 should have authority for file_read")

	ok, err = v.VerifyAuthority("agent-1", "file_write")
	require.NoError(t, err)
	assert.True(t, ok, "agent-1 should have authority for file_write")
}

func TestAIPVerifier_VerifyAuthorityRejected(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	v := NewAIPVerifier(WithAIPClock(aipFixedClock(now)))

	err := v.RegisterDelegation(DelegationClaim{
		DelegatorID: "user-1",
		DelegateID:  "agent-1",
		Scope:       []string{"file_read"},
		ExpiresAt:   now.Add(time.Hour),
	})
	require.NoError(t, err)

	ok, err := v.VerifyAuthority("agent-1", "file_delete")
	require.NoError(t, err)
	assert.False(t, ok, "agent-1 should NOT have authority for file_delete")
}

func TestAIPVerifier_ExpiredDelegationRejected(t *testing.T) {
	past := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)

	// Register at past time.
	v := NewAIPVerifier(WithAIPClock(aipFixedClock(past)))
	err := v.RegisterDelegation(DelegationClaim{
		DelegatorID: "user-1",
		DelegateID:  "agent-1",
		Scope:       []string{"file_read"},
		ExpiresAt:   past.Add(time.Hour), // Expired relative to "now"
	})
	require.NoError(t, err)

	// Verify at current time — delegation has expired.
	v2 := NewAIPVerifier(WithAIPClock(aipFixedClock(now)))
	// Copy the chain manually.
	chain := v.GetChain("agent-1")
	for _, c := range chain {
		_ = v2.RegisterDelegation(c)
	}

	ok, err := v2.VerifyAuthority("agent-1", "file_read")
	require.NoError(t, err)
	assert.False(t, ok, "expired delegation should be rejected")
}

func TestAIPVerifier_ScopeNarrowingEnforced(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	v := NewAIPVerifier(WithAIPClock(aipFixedClock(now)))

	// Delegator "agent-1" has scope [file_read, file_write].
	err := v.RegisterDelegation(DelegationClaim{
		DelegatorID: "user-1",
		DelegateID:  "agent-1",
		Scope:       []string{"file_read", "file_write"},
		ExpiresAt:   now.Add(time.Hour),
	})
	require.NoError(t, err)

	// Agent-1 sub-delegates to agent-2 with narrowed scope — allowed.
	err = v.RegisterDelegation(DelegationClaim{
		DelegatorID: "agent-1",
		DelegateID:  "agent-2",
		Scope:       []string{"file_read"},
		ExpiresAt:   now.Add(30 * time.Minute),
	})
	require.NoError(t, err)

	// Agent-1 tries to sub-delegate a tool it does NOT have — rejected.
	err = v.RegisterDelegation(DelegationClaim{
		DelegatorID: "agent-1",
		DelegateID:  "agent-3",
		Scope:       []string{"file_read", "file_delete"},
		ExpiresAt:   now.Add(30 * time.Minute),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope narrowing violation")
	assert.Contains(t, err.Error(), "file_delete")
}

func TestAIPVerifier_ChainOfDelegations(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	v := NewAIPVerifier(WithAIPClock(aipFixedClock(now)))

	// User -> Agent-1 (file_read, file_write, db_query)
	err := v.RegisterDelegation(DelegationClaim{
		DelegatorID: "user-1",
		DelegateID:  "agent-1",
		Scope:       []string{"file_read", "file_write", "db_query"},
		ExpiresAt:   now.Add(2 * time.Hour),
	})
	require.NoError(t, err)

	// Agent-1 -> Agent-2 (file_read, db_query) — narrowed
	err = v.RegisterDelegation(DelegationClaim{
		DelegatorID: "agent-1",
		DelegateID:  "agent-2",
		Scope:       []string{"file_read", "db_query"},
		ExpiresAt:   now.Add(time.Hour),
	})
	require.NoError(t, err)

	// Agent-2 -> Agent-3 (file_read) — further narrowed
	err = v.RegisterDelegation(DelegationClaim{
		DelegatorID: "agent-2",
		DelegateID:  "agent-3",
		Scope:       []string{"file_read"},
		ExpiresAt:   now.Add(30 * time.Minute),
	})
	require.NoError(t, err)

	// Verify agent-3's authority.
	ok, err := v.VerifyAuthority("agent-3", "file_read")
	require.NoError(t, err)
	assert.True(t, ok, "agent-3 should have file_read")

	ok, err = v.VerifyAuthority("agent-3", "db_query")
	require.NoError(t, err)
	assert.False(t, ok, "agent-3 should NOT have db_query (narrowed out)")
}

func TestAIPVerifier_NoDelegationFailsClosed(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	v := NewAIPVerifier(WithAIPClock(aipFixedClock(now)))

	ok, err := v.VerifyAuthority("unknown-agent", "file_read")
	require.NoError(t, err)
	assert.False(t, ok, "no delegation should fail closed")
}

func TestAIPVerifier_GetChainReturnsCopy(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	v := NewAIPVerifier(WithAIPClock(aipFixedClock(now)))

	err := v.RegisterDelegation(DelegationClaim{
		DelegatorID: "user-1",
		DelegateID:  "agent-1",
		Scope:       []string{"file_read"},
		ExpiresAt:   now.Add(time.Hour),
	})
	require.NoError(t, err)

	chain := v.GetChain("agent-1")
	require.Len(t, chain, 1)

	// Mutate returned chain.
	chain[0].Scope = []string{"TAMPERED"}

	// Internal state should be unaffected.
	chain2 := v.GetChain("agent-1")
	assert.Equal(t, []string{"file_read"}, chain2[0].Scope)
}

func TestAIPVerifier_GetChainNotFound(t *testing.T) {
	v := NewAIPVerifier()

	chain := v.GetChain("nonexistent")
	assert.Nil(t, chain)
}

func TestAIPVerifier_ValidationErrors(t *testing.T) {
	v := NewAIPVerifier()

	t.Run("empty delegator", func(t *testing.T) {
		err := v.RegisterDelegation(DelegationClaim{
			DelegateID: "agent-1",
			Scope:      []string{"tool"},
			ExpiresAt:  time.Now().Add(time.Hour),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delegator ID")
	})

	t.Run("empty delegate", func(t *testing.T) {
		err := v.RegisterDelegation(DelegationClaim{
			DelegatorID: "user-1",
			Scope:       []string{"tool"},
			ExpiresAt:   time.Now().Add(time.Hour),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delegate ID")
	})

	t.Run("empty scope", func(t *testing.T) {
		err := v.RegisterDelegation(DelegationClaim{
			DelegatorID: "user-1",
			DelegateID:  "agent-1",
			Scope:       []string{},
			ExpiresAt:   time.Now().Add(time.Hour),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scope")
	})

	t.Run("verify empty delegate ID", func(t *testing.T) {
		_, err := v.VerifyAuthority("", "tool")
		require.Error(t, err)
	})

	t.Run("verify empty tool name", func(t *testing.T) {
		_, err := v.VerifyAuthority("agent-1", "")
		require.Error(t, err)
	})
}

func TestAIPVerifier_ConcurrentAccess(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	v := NewAIPVerifier(WithAIPClock(aipFixedClock(now)))

	var wg sync.WaitGroup

	// Concurrent registrations.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = v.RegisterDelegation(DelegationClaim{
				DelegatorID: "user-1",
				DelegateID:  "agent-concurrent",
				Scope:       []string{"tool_a", "tool_b"},
				ExpiresAt:   now.Add(time.Hour),
			})
		}(i)
	}

	// Concurrent verifications.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = v.VerifyAuthority("agent-concurrent", "tool_a")
		}()
	}

	// Concurrent chain reads.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = v.GetChain("agent-concurrent")
		}()
	}

	wg.Wait()

	// Verify state is consistent — no panics, chain exists.
	chain := v.GetChain("agent-concurrent")
	assert.NotEmpty(t, chain)
}
