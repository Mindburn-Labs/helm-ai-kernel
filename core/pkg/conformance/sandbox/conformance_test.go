package sandbox

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conformance"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSandboxConformance_MockActuator(t *testing.T) {
	mock := NewMockActuator()
	suite := conformance.NewSuite()
	RegisterSandboxTests(suite, mock)

	// Run L1 tests.
	t.Run("L1", func(t *testing.T) {
		results := suite.Run(conformance.LevelL1)
		for _, r := range results {
			t.Run(r.Name, func(t *testing.T) {
				if !r.Passed {
					t.Fatalf("FAIL: %s — %s", r.TestID, r.Error)
				}
				t.Logf("PASS: %s (%v)", r.TestID, r.Duration)
			})
		}
	})

	// Run L2 tests (includes L1).
	t.Run("L2", func(t *testing.T) {
		results := suite.Run(conformance.LevelL2)
		for _, r := range results {
			t.Run(r.Name, func(t *testing.T) {
				if !r.Passed {
					t.Fatalf("FAIL: %s — %s", r.TestID, r.Error)
				}
			})
		}
	})

	// Run L3 tests (includes L1+L2).
	t.Run("L3", func(t *testing.T) {
		results := suite.Run(conformance.LevelL3)
		for _, r := range results {
			t.Run(r.Name, func(t *testing.T) {
				if !r.Passed {
					t.Fatalf("FAIL: %s — %s", r.TestID, r.Error)
				}
			})
		}
	})
}

func TestReceiptDeterminism(t *testing.T) {
	mock := NewMockActuator()
	req := &actuators.ExecRequest{Command: []string{"echo", "deterministic"}}

	ok, err := VerifyReceiptDeterminism(mock, req)
	require.NoError(t, err)
	assert.True(t, ok, "receipt hashes must be identical for identical commands")
}

func TestMockActuator_Lifecycle(t *testing.T) {
	mock := NewMockActuator()
	ctx := t.Context()

	// Create.
	handle, err := mock.Create(ctx, defaultSpec())
	require.NoError(t, err)
	assert.Equal(t, actuators.StatusRunning, handle.Status)

	// Pause.
	require.NoError(t, mock.Pause(ctx, handle.ID))

	// Resume.
	resumed, err := mock.Resume(ctx, handle.ID)
	require.NoError(t, err)
	assert.Equal(t, actuators.StatusRunning, resumed.Status)

	// Terminate.
	require.NoError(t, mock.Terminate(ctx, handle.ID))

	// Operations on terminated sandbox should fail.
	err = mock.Pause(ctx, handle.ID)
	assert.ErrorIs(t, err, actuators.ErrSandboxTerminated)
}

func TestMockActuator_FileSystem(t *testing.T) {
	mock := NewMockActuator()
	ctx := t.Context()

	handle, err := mock.Create(ctx, defaultSpec())
	require.NoError(t, err)
	defer mock.Terminate(ctx, handle.ID) //nolint:errcheck

	data := []byte("hello world")
	require.NoError(t, mock.WriteFile(ctx, handle.ID, "/test.txt", data))

	got, err := mock.ReadFile(ctx, handle.ID, "/test.txt")
	require.NoError(t, err)
	assert.Equal(t, data, got)

	// Verify the file wasn't aliased (copy semantics).
	data[0] = 'X'
	got2, _ := mock.ReadFile(ctx, handle.ID, "/test.txt")
	assert.Equal(t, byte('h'), got2[0], "WriteFile must copy data, not alias")
}

func TestMockActuator_NotFound(t *testing.T) {
	mock := NewMockActuator()
	ctx := t.Context()

	_, err := mock.Resume(ctx, "nonexistent")
	assert.ErrorIs(t, err, actuators.ErrSandboxNotFound)

	err = mock.Pause(ctx, "nonexistent")
	assert.ErrorIs(t, err, actuators.ErrSandboxNotFound)

	err = mock.Terminate(ctx, "nonexistent")
	assert.ErrorIs(t, err, actuators.ErrSandboxNotFound)
}
