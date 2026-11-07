package governance

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCELDPProfileID verifies profile constant.
func TestCELDPProfileID(t *testing.T) {
	require.Equal(t, "cel-dp-v1", CELDPProfileID)
}
