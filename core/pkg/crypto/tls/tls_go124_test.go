//go:build go1.24

package tls

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHybridPQCConfig(t *testing.T) {
	config := HybridPQCConfig()

	require.NotNil(t, config)
	require.Equal(t, uint16(tls.VersionTLS13), config.MinVersion)
	require.Contains(t, config.CurvePreferences, tls.X25519MLKEM768)
	require.Contains(t, config.CurvePreferences, tls.X25519)
}

func TestClientConfig(t *testing.T) {
	config := ClientConfig("example.com")

	require.NotNil(t, config)
	require.Equal(t, "example.com", config.ServerName)
	require.Contains(t, config.CurvePreferences, tls.X25519MLKEM768)
}

func TestInsecureClientConfig(t *testing.T) {
	config := InsecureClientConfig()

	require.NotNil(t, config)
	require.True(t, config.InsecureSkipVerify)
}

func TestIsHybridPQCSupported(t *testing.T) {
	// Should return true on Go 1.24+
	require.True(t, IsHybridPQCSupported())
}

func TestCurvePreferenceOrder(t *testing.T) {
	config := HybridPQCConfig()

	// X25519MLKEM768 should be first (preferred)
	require.Equal(t, tls.X25519MLKEM768, config.CurvePreferences[0])
	// X25519 should be fallback
	require.Equal(t, tls.X25519, config.CurvePreferences[1])
}
