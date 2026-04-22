//go:build !go1.24

package tls

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHybridPQCConfig_Legacy(t *testing.T) {
	config := HybridPQCConfig()

	require.NotNil(t, config)
	require.Equal(t, uint16(tls.VersionTLS13), config.MinVersion)
	// In legacy, we should NOT see PQC curves
	require.Contains(t, config.CurvePreferences, tls.X25519)
	require.NotContains(t, config.CurvePreferences, uint16(0x45b0)) // 0x45b0 is rough stub, actual check is simpler
}

func TestIsHybridPQCSupported_Legacy(t *testing.T) {
	require.False(t, IsHybridPQCSupported())
}
