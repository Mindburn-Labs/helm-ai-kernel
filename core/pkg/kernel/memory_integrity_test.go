package kernel

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryIntegrityStore_WriteAndReadRoundTrip(t *testing.T) {
	store := NewMemoryIntegrityStore()

	entry, err := store.Write("config", []byte(`{"model":"gpt-4"}`), "agent-1")
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.Equal(t, "config", entry.Key)
	assert.Equal(t, []byte(`{"model":"gpt-4"}`), entry.Value)
	assert.Equal(t, "agent-1", entry.WrittenBy)
	assert.Equal(t, 1, entry.Version)
	assert.NotEmpty(t, entry.ContentHash)

	// Read back
	read, err := store.Read("config")
	require.NoError(t, err)
	assert.Equal(t, entry.Value, read.Value)
	assert.Equal(t, entry.ContentHash, read.ContentHash)
	assert.Equal(t, entry.Version, read.Version)
}

func TestMemoryIntegrityStore_ReadNotFound(t *testing.T) {
	store := NewMemoryIntegrityStore()

	_, err := store.Read("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMemoryIntegrityStore_HashVerification(t *testing.T) {
	store := NewMemoryIntegrityStore()

	_, err := store.Write("key1", []byte("hello world"), "agent-1")
	require.NoError(t, err)

	// Normal read should succeed
	err = store.Verify("key1")
	require.NoError(t, err)

	// Read should also succeed
	entry, err := store.Read("key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("hello world"), entry.Value)
}

func TestMemoryIntegrityStore_TamperDetection(t *testing.T) {
	store := NewMemoryIntegrityStore()

	_, err := store.Write("secret", []byte("original-value"), "agent-1")
	require.NoError(t, err)

	// Simulate tampering by directly mutating the internal entry
	store.mu.Lock()
	store.entries["secret"].Value = []byte("tampered-value")
	store.mu.Unlock()

	// Read must detect tampering
	_, err = store.Read("secret")
	require.Error(t, err)

	var tamperErr *ErrMemoryTampered
	require.True(t, errors.As(err, &tamperErr), "error should be *ErrMemoryTampered")
	assert.Equal(t, "secret", tamperErr.Key)
	assert.NotEqual(t, tamperErr.ExpectedHash, tamperErr.ActualHash)

	// Verify must also detect tampering
	err = store.Verify("secret")
	require.Error(t, err)
	require.True(t, errors.As(err, &tamperErr))
}

func TestMemoryIntegrityStore_VersionIncrementing(t *testing.T) {
	store := NewMemoryIntegrityStore()

	e1, err := store.Write("counter", []byte("v1"), "agent-1")
	require.NoError(t, err)
	assert.Equal(t, 1, e1.Version)

	e2, err := store.Write("counter", []byte("v2"), "agent-1")
	require.NoError(t, err)
	assert.Equal(t, 2, e2.Version)

	e3, err := store.Write("counter", []byte("v3"), "agent-2")
	require.NoError(t, err)
	assert.Equal(t, 3, e3.Version)

	// Read should return latest version
	read, err := store.Read("counter")
	require.NoError(t, err)
	assert.Equal(t, 3, read.Version)
	assert.Equal(t, []byte("v3"), read.Value)
}

func TestMemoryIntegrityStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryIntegrityStore()

	const goroutines = 50
	const writesPerGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				key := fmt.Sprintf("key-%d", id)
				value := []byte(fmt.Sprintf("value-%d-%d", id, j))
				principal := fmt.Sprintf("agent-%d", id)

				_, err := store.Write(key, value, principal)
				assert.NoError(t, err)

				// Interleave reads
				entry, err := store.Read(key)
				if err == nil {
					assert.NotEmpty(t, entry.ContentHash)
				}
			}
		}(i)
	}

	wg.Wait()

	// All keys should be readable and intact
	for i := 0; i < goroutines; i++ {
		key := fmt.Sprintf("key-%d", i)
		err := store.Verify(key)
		assert.NoError(t, err, "key %s should pass integrity check after concurrent writes", key)
	}
}

func TestMemoryIntegrityStore_Delete(t *testing.T) {
	store := NewMemoryIntegrityStore()

	_, err := store.Write("ephemeral", []byte("data"), "agent-1")
	require.NoError(t, err)

	err = store.Delete("ephemeral")
	require.NoError(t, err)

	// Read after delete should fail
	_, err = store.Read("ephemeral")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Delete of non-existent key should error
	err = store.Delete("ephemeral")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMemoryIntegrityStore_DeletePreservesHistory(t *testing.T) {
	store := NewMemoryIntegrityStore()

	_, err := store.Write("temp", []byte("v1"), "agent-1")
	require.NoError(t, err)
	_, err = store.Write("temp", []byte("v2"), "agent-1")
	require.NoError(t, err)

	err = store.Delete("temp")
	require.NoError(t, err)

	// History should still show both writes even after deletion
	history := store.History("temp")
	assert.Len(t, history, 2)
	assert.Equal(t, 1, history[0].Version)
	assert.Equal(t, 2, history[1].Version)
}

func TestMemoryIntegrityStore_HistoryTracking(t *testing.T) {
	store := NewMemoryIntegrityStore()

	_, _ = store.Write("log", []byte("entry-1"), "agent-1")
	_, _ = store.Write("log", []byte("entry-2"), "agent-2")
	_, _ = store.Write("other", []byte("unrelated"), "agent-3")
	_, _ = store.Write("log", []byte("entry-3"), "agent-1")

	// Key-specific history
	logHistory := store.History("log")
	assert.Len(t, logHistory, 3)
	assert.Equal(t, "agent-1", logHistory[0].WrittenBy)
	assert.Equal(t, "agent-2", logHistory[1].WrittenBy)
	assert.Equal(t, "agent-1", logHistory[2].WrittenBy)

	// Version chain
	assert.Equal(t, 1, logHistory[0].Version)
	assert.Equal(t, 2, logHistory[1].Version)
	assert.Equal(t, 3, logHistory[2].Version)

	// Previous hash chain
	assert.Empty(t, logHistory[0].PreviousHash, "first write has no previous hash")
	assert.Equal(t, logHistory[0].ContentHash, logHistory[1].PreviousHash)
	assert.Equal(t, logHistory[1].ContentHash, logHistory[2].PreviousHash)
}

func TestMemoryIntegrityStore_AllHistory(t *testing.T) {
	store := NewMemoryIntegrityStore()

	_, _ = store.Write("a", []byte("1"), "agent-1")
	_, _ = store.Write("b", []byte("2"), "agent-2")
	_, _ = store.Write("a", []byte("3"), "agent-1")

	all := store.AllHistory()
	assert.Len(t, all, 3)
	assert.Equal(t, "a", all[0].Key)
	assert.Equal(t, "b", all[1].Key)
	assert.Equal(t, "a", all[2].Key)
}

func TestMemoryIntegrityStore_ClockInjection(t *testing.T) {
	fixedTime := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixedTime }

	store := NewMemoryIntegrityStore(WithIntegrityClock(clock))

	entry, err := store.Write("key", []byte("value"), "agent-1")
	require.NoError(t, err)
	assert.Equal(t, fixedTime, entry.WrittenAt)

	read, err := store.Read("key")
	require.NoError(t, err)
	assert.Equal(t, fixedTime, read.WrittenAt)

	history := store.History("key")
	require.Len(t, history, 1)
	assert.Equal(t, fixedTime, history[0].WrittenAt)
}

func TestMemoryIntegrityStore_WriteDifferentPrincipals(t *testing.T) {
	store := NewMemoryIntegrityStore()

	e1, err := store.Write("shared-config", []byte(`{"timeout":30}`), "admin-1")
	require.NoError(t, err)
	assert.Equal(t, "admin-1", e1.WrittenBy)
	assert.Equal(t, 1, e1.Version)

	e2, err := store.Write("shared-config", []byte(`{"timeout":60}`), "admin-2")
	require.NoError(t, err)
	assert.Equal(t, "admin-2", e2.WrittenBy)
	assert.Equal(t, 2, e2.Version)

	// Read returns latest writer
	read, err := store.Read("shared-config")
	require.NoError(t, err)
	assert.Equal(t, "admin-2", read.WrittenBy)

	// History captures both principals
	history := store.History("shared-config")
	assert.Equal(t, "admin-1", history[0].WrittenBy)
	assert.Equal(t, "admin-2", history[1].WrittenBy)
}

func TestErrMemoryTampered_TypeAssertion(t *testing.T) {
	err := &ErrMemoryTampered{
		Key:          "credentials",
		ExpectedHash: "abc123",
		ActualHash:   "xyz789",
	}

	// Verify it implements error interface
	var genericErr error = err
	assert.Contains(t, genericErr.Error(), "memory tampered")
	assert.Contains(t, genericErr.Error(), "credentials")
	assert.Contains(t, genericErr.Error(), "abc123")
	assert.Contains(t, genericErr.Error(), "xyz789")

	// Type assertion via errors.As
	var tamperErr *ErrMemoryTampered
	assert.True(t, errors.As(genericErr, &tamperErr))
	assert.Equal(t, "credentials", tamperErr.Key)
}

func TestMemoryIntegrityStore_EmptyValue(t *testing.T) {
	store := NewMemoryIntegrityStore()

	entry, err := store.Write("empty", []byte{}, "agent-1")
	require.NoError(t, err)
	assert.NotEmpty(t, entry.ContentHash, "empty value should still produce a hash")

	read, err := store.Read("empty")
	require.NoError(t, err)
	assert.Equal(t, []byte{}, read.Value)
}

func TestMemoryIntegrityStore_EmptyKeyRejected(t *testing.T) {
	store := NewMemoryIntegrityStore()

	_, err := store.Write("", []byte("value"), "agent-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key must not be empty")
}

func TestMemoryIntegrityStore_ValueIsolation(t *testing.T) {
	store := NewMemoryIntegrityStore()

	// Write with a slice, then mutate the original — store must be unaffected
	original := []byte("original-data")
	_, err := store.Write("isolated", original, "agent-1")
	require.NoError(t, err)

	// Mutate the original slice
	original[0] = 'X'

	read, err := store.Read("isolated")
	require.NoError(t, err)
	assert.Equal(t, []byte("original-data"), read.Value, "store must not be affected by external mutation")

	// Mutate the returned slice — store must still be intact
	read.Value[0] = 'Y'

	read2, err := store.Read("isolated")
	require.NoError(t, err)
	assert.Equal(t, []byte("original-data"), read2.Value, "store must not be affected by read-result mutation")
}

func TestMemoryIntegrityStore_VerifyNotFound(t *testing.T) {
	store := NewMemoryIntegrityStore()

	err := store.Verify("ghost")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMemoryIntegrityStore_HistoryEmptyForUnknownKey(t *testing.T) {
	store := NewMemoryIntegrityStore()

	history := store.History("unknown")
	assert.Empty(t, history)
}

func TestMemoryIntegrityStore_AllHistoryEmpty(t *testing.T) {
	store := NewMemoryIntegrityStore()

	all := store.AllHistory()
	assert.Empty(t, all)
}

func TestMemoryIntegrityStore_HashDeterminism(t *testing.T) {
	store := NewMemoryIntegrityStore()

	// Same value written twice should produce the same hash
	e1, _ := store.Write("a", []byte("deterministic"), "agent-1")
	// Delete and re-write
	_ = store.Delete("a")
	e2, _ := store.Write("a", []byte("deterministic"), "agent-2")

	assert.Equal(t, e1.ContentHash, e2.ContentHash,
		"same content must always produce the same hash")
}
