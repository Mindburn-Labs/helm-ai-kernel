package governance

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestBlockingStateCreation verifies blocking state creation.
func TestBlockingStateCreation(t *testing.T) {
	t.Run("create approval state", func(t *testing.T) {
		bs := NewApprovalState("approval-1", 1*time.Hour)
		require.Equal(t, "approval-1", bs.StateID)
		require.Equal(t, BlockingStateApproval, bs.StateType)
		require.Equal(t, LivenessStatePending, bs.State)
		require.False(t, bs.IsExpired())
	})

	t.Run("create obligation state", func(t *testing.T) {
		bs := NewObligationState("obligation-1", 0) // Use default
		require.Equal(t, BlockingStateObligation, bs.StateType)
		require.Equal(t, DefaultObligationTimeout, bs.Timeout)
	})

	t.Run("create sequencer lease", func(t *testing.T) {
		bs := NewSequencerLease("lease-1", 15*time.Second)
		require.Equal(t, BlockingStateLease, bs.StateType)
		require.Equal(t, 15*time.Second, bs.Timeout)
	})
}

// TestBlockingStateLifecycle verifies state transitions.
func TestBlockingStateLifecycle(t *testing.T) {
	t.Run("resolve state", func(t *testing.T) {
		bs := NewApprovalState("test-1", 1*time.Minute)
		require.Equal(t, LivenessStatePending, bs.State)

		bs.Resolve()
		require.Equal(t, LivenessStateActive, bs.State)
		require.NotNil(t, bs.ResolvedAt)
	})

	t.Run("cancel state", func(t *testing.T) {
		bs := NewApprovalState("test-2", 1*time.Minute)
		bs.Cancel()
		require.Equal(t, LivenessStateCanceled, bs.State)
	})

	t.Run("expire state", func(t *testing.T) {
		bs := NewApprovalState("test-3", 1*time.Minute)

		expired := false
		bs.OnExpire(func(s *BlockingState) {
			expired = true
		})

		bs.Expire()
		require.Equal(t, LivenessStateExpired, bs.State)
		require.True(t, expired)
	})
}

// TestBlockingStateExpiry verifies expiry checking.
func TestBlockingStateExpiry(t *testing.T) {
	t.Run("not expired initially", func(t *testing.T) {
		bs := NewApprovalState("test", 1*time.Hour)
		require.False(t, bs.IsExpired())
		require.True(t, bs.TimeRemaining() > 0)
	})

	t.Run("expired after timeout", func(t *testing.T) {
		bs := NewApprovalState("test", 1*time.Millisecond)
		time.Sleep(5 * time.Millisecond)
		require.True(t, bs.IsExpired())
		require.Equal(t, time.Duration(0), bs.TimeRemaining())
	})
}

// TestBlockingStateExtension verifies expiry extension.
func TestBlockingStateExtension(t *testing.T) {
	t.Run("extend pending state", func(t *testing.T) {
		bs := NewApprovalState("test", 1*time.Second)
		originalExpiry := bs.ExpiresAt

		time.Sleep(100 * time.Millisecond)
		err := bs.Extend(2 * time.Second)
		require.NoError(t, err)
		require.True(t, bs.ExpiresAt.After(originalExpiry))
	})

	t.Run("cannot extend resolved state", func(t *testing.T) {
		bs := NewApprovalState("test", 1*time.Second)
		bs.Resolve()

		err := bs.Extend(2 * time.Second)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot extend")
	})
}

// TestLivenessManager verifies manager operations.
func TestLivenessManager(t *testing.T) {
	t.Run("register and get", func(t *testing.T) {
		lm := NewLivenessManager()
		defer lm.Shutdown()

		bs := NewApprovalState("approval-1", 1*time.Minute)
		err := lm.Register(bs)
		require.NoError(t, err)

		retrieved, err := lm.Get("approval-1")
		require.NoError(t, err)
		require.Equal(t, bs.StateID, retrieved.StateID)
	})

	t.Run("duplicate registration fails", func(t *testing.T) {
		lm := NewLivenessManager()
		defer lm.Shutdown()

		bs := NewApprovalState("approval-1", 1*time.Minute)
		err := lm.Register(bs)
		require.NoError(t, err)

		err = lm.Register(bs)
		require.Error(t, err)
		require.Contains(t, err.Error(), "already registered")
	})

	t.Run("get unknown fails", func(t *testing.T) {
		lm := NewLivenessManager()
		defer lm.Shutdown()

		_, err := lm.Get("unknown")
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found")
	})
}

// TestLivenessManagerResolve verifies resolution.
func TestLivenessManagerResolve(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()

	t.Run("resolve pending state", func(t *testing.T) {
		bs := NewApprovalState("approval-1", 1*time.Minute)
		_ = lm.Register(bs)

		err := lm.Resolve("approval-1")
		require.NoError(t, err)

		resolved, _ := lm.Get("approval-1")
		require.Equal(t, LivenessStateActive, resolved.State)
	})

	t.Run("resolve unknown fails", func(t *testing.T) {
		err := lm.Resolve("unknown")
		require.Error(t, err)
	})
}

// TestLivenessManagerCancel verifies cancellation.
func TestLivenessManagerCancel(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()

	bs := NewApprovalState("approval-1", 1*time.Minute)
	_ = lm.Register(bs)

	err := lm.Cancel("approval-1")
	require.NoError(t, err)

	canceled, _ := lm.Get("approval-1")
	require.Equal(t, LivenessStateCanceled, canceled.State)
}

// TestLivenessManagerActiveCount verifies counting.
func TestLivenessManagerActiveCount(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()

	require.Equal(t, 0, lm.ActiveCount())

	_ = lm.Register(NewApprovalState("a1", 1*time.Minute))
	_ = lm.Register(NewApprovalState("a2", 1*time.Minute))
	require.Equal(t, 2, lm.ActiveCount())

	_ = lm.Cancel("a1")
	require.Equal(t, 1, lm.ActiveCount())
}

// TestLivenessManagerPendingApprovals verifies filtering.
func TestLivenessManagerPendingApprovals(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()

	_ = lm.Register(NewApprovalState("a1", 1*time.Minute))
	_ = lm.Register(NewApprovalState("a2", 1*time.Minute))
	_ = lm.Register(NewObligationState("o1", 1*time.Minute))

	approvals := lm.PendingApprovals()
	require.Len(t, approvals, 2)
}

// TestLivenessAutoExpiry verifies automatic expiry.
func TestLivenessAutoExpiry(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()

	bs := NewApprovalState("short-lived", 50*time.Millisecond)
	_ = lm.Register(bs)

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	expired, _ := lm.Get("short-lived")
	require.Equal(t, LivenessStateExpired, expired.State)
}
