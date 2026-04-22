package mcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionStore_CreateAndGet(t *testing.T) {
	store := NewSessionStore(5 * time.Minute)
	defer store.Stop()

	id, err := store.Create(LatestProtocolVersion, "test-client")
	require.NoError(t, err)
	require.NotEmpty(t, id)

	session := store.Get(id)
	require.NotNil(t, session)
	assert.Equal(t, id, session.ID)
	assert.Equal(t, LatestProtocolVersion, session.ProtocolVersion)
	assert.Equal(t, "test-client", session.ClientName)
	assert.WithinDuration(t, time.Now(), session.CreatedAt, 2*time.Second)
}

func TestSessionStore_GetUpdatesLastAccess(t *testing.T) {
	store := NewSessionStore(5 * time.Minute)
	defer store.Stop()

	id, err := store.Create(LatestProtocolVersion, "")
	require.NoError(t, err)

	session := store.Get(id)
	require.NotNil(t, session)
	firstAccess := session.LastAccess

	time.Sleep(5 * time.Millisecond)

	session = store.Get(id)
	require.NotNil(t, session)
	assert.True(t, session.LastAccess.After(firstAccess))
}

func TestSessionStore_ExpiredSessionReturnsNil(t *testing.T) {
	store := NewSessionStore(50 * time.Millisecond)
	defer store.Stop()

	id, err := store.Create(LatestProtocolVersion, "")
	require.NoError(t, err)

	time.Sleep(60 * time.Millisecond)

	session := store.Get(id)
	assert.Nil(t, session)
}

func TestSessionStore_Delete(t *testing.T) {
	store := NewSessionStore(5 * time.Minute)
	defer store.Stop()

	id, err := store.Create(LatestProtocolVersion, "")
	require.NoError(t, err)

	store.Delete(id)
	assert.Nil(t, store.Get(id))
}

func TestSessionStore_Len(t *testing.T) {
	store := NewSessionStore(5 * time.Minute)
	defer store.Stop()

	assert.Equal(t, 0, store.Len())

	_, _ = store.Create(LatestProtocolVersion, "a")
	_, _ = store.Create(LatestProtocolVersion, "b")
	assert.Equal(t, 2, store.Len())
}

func TestSessionStore_UnknownIDReturnsNil(t *testing.T) {
	store := NewSessionStore(5 * time.Minute)
	defer store.Stop()

	assert.Nil(t, store.Get("nonexistent"))
}

func TestSessionStore_ConcurrentAccess(t *testing.T) {
	store := NewSessionStore(5 * time.Minute)
	defer store.Stop()

	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			id, err := store.Create(LatestProtocolVersion, "concurrent")
			if err != nil {
				return
			}
			_ = store.Get(id)
			store.Delete(id)
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}

func TestSessionStore_ReaperEvictsExpiredSessions(t *testing.T) {
	store := NewSessionStore(50 * time.Millisecond)
	defer store.Stop()

	_, _ = store.Create(LatestProtocolVersion, "reap-me")
	assert.Equal(t, 1, store.Len())

	// Wait for session to expire.
	time.Sleep(60 * time.Millisecond)

	// Trigger reap explicitly (avoids flaky goroutine scheduling).
	store.reap()

	assert.Equal(t, 0, store.Len())
}
