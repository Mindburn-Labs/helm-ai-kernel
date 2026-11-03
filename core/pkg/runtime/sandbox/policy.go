// Package sandbox declares sandbox policies, backend profiles, and sealed
// sandbox grants. It records declarations only; it does not execute packs.
package sandbox

// SandboxPolicy defines the security boundary for a sandbox.
type SandboxPolicy struct {
	PolicyID         string   `json:"policy_id"`
	FSAllowlist      []string `json:"fs_allowlist"`      // Allowed filesystem paths (prefixes)
	FSDenylist       []string `json:"fs_denylist"`       // Denied paths (checked first)
	NetworkAllowlist []string `json:"network_allowlist"` // Allowed hosts/CIDRs
	NetworkDenyAll   bool     `json:"network_deny_all"`  // If true, block all network
	NetworkPosture   string   `json:"network_posture,omitempty"`
	MaxMemoryBytes   int64    `json:"max_memory_bytes"`
	MaxCPUSeconds    int64    `json:"max_cpu_seconds"`
	Capabilities     []string `json:"capabilities"` // Allowed capabilities
	MaxOpenFiles     int      `json:"max_open_files"`
	ReadOnly         bool     `json:"read_only"` // FS is read-only
}

// DefaultPolicy returns a restrictive default sandbox policy.
func DefaultPolicy() *SandboxPolicy {
	return &SandboxPolicy{
		PolicyID:       "default",
		FSAllowlist:    []string{"/tmp/sandbox"},
		FSDenylist:     []string{"/etc/passwd", "/etc/shadow", "/root"},
		NetworkDenyAll: true,
		MaxMemoryBytes: 256 * 1024 * 1024, // 256MB
		MaxCPUSeconds:  30,
		Capabilities:   []string{"read", "write", "execute"},
		MaxOpenFiles:   64,
		ReadOnly:       false,
	}
}
