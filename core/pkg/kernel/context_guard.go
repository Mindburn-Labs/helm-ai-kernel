package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ContextGuard validates environment fingerprints to detect environment
// recreation or tampering attacks (e.g., Kiro-style env-recreate).
//
// The guard captures a boot-time fingerprint of the execution environment
// and compares it against the current fingerprint before each enforcement
// decision. Any mismatch results in a CONTEXT_MISMATCH denial.
//
// Design invariants:
//   - Boot fingerprint is captured once and immutable
//   - Comparison is deterministic and repeatable
//   - Nil guard (no boot fingerprint) is a pass-through for backward compat
//   - Clock is injected for deterministic testing
type ContextGuard struct {
	mu              sync.RWMutex
	bootFingerprint string
	bootTime        time.Time
	validationCount int64
	mismatchCount   int64
	clock           func() time.Time
}

// ContextMismatchError is returned when the current environment fingerprint
// does not match the boot-time fingerprint.
type ContextMismatchError struct {
	BootFingerprint    string    `json:"boot_fingerprint"`
	CurrentFingerprint string    `json:"current_fingerprint"`
	BootTime           time.Time `json:"boot_time"`
	DetectedAt         time.Time `json:"detected_at"`
}

func (e *ContextMismatchError) Error() string {
	return fmt.Sprintf("CONTEXT_MISMATCH: boot=%s current=%s", e.BootFingerprint[:12], e.CurrentFingerprint[:12])
}

// NewContextGuard creates a ContextGuard with a boot-time fingerprint
// computed from the current environment.
func NewContextGuard() *ContextGuard {
	cg := &ContextGuard{
		clock: time.Now,
	}
	cg.bootFingerprint = cg.computeFingerprint()
	cg.bootTime = cg.clock()
	return cg
}

// NewContextGuardWithFingerprint creates a ContextGuard with an explicit
// boot fingerprint. Used for testing or when the fingerprint is provided
// externally (e.g., from a signed boot attestation).
func NewContextGuardWithFingerprint(fingerprint string) *ContextGuard {
	return &ContextGuard{
		bootFingerprint: fingerprint,
		bootTime:        time.Now(),
		clock:           time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (cg *ContextGuard) WithClock(clock func() time.Time) *ContextGuard {
	cg.clock = clock
	return cg
}

// BootFingerprint returns the boot-time fingerprint.
func (cg *ContextGuard) BootFingerprint() string {
	return cg.bootFingerprint
}

// Validate compares the provided fingerprint against the boot fingerprint.
// Returns nil on match, ContextMismatchError on mismatch.
//
// If the boot fingerprint is empty (no guard configured), validation
// is a no-op pass-through for backward compatibility.
func (cg *ContextGuard) Validate(currentFingerprint string) error {
	cg.mu.Lock()
	defer cg.mu.Unlock()

	cg.validationCount++

	// No boot fingerprint = pass-through (backward compat)
	if cg.bootFingerprint == "" {
		return nil
	}

	if currentFingerprint != cg.bootFingerprint {
		cg.mismatchCount++
		return &ContextMismatchError{
			BootFingerprint:    cg.bootFingerprint,
			CurrentFingerprint: currentFingerprint,
			BootTime:           cg.bootTime,
			DetectedAt:         cg.clock(),
		}
	}

	return nil
}

// ValidateCurrent computes the current environment fingerprint and
// validates it against the boot fingerprint. Convenience method for
// real-time validation without external fingerprint computation.
func (cg *ContextGuard) ValidateCurrent() error {
	return cg.Validate(cg.computeFingerprint())
}

// Stats returns validation statistics.
func (cg *ContextGuard) Stats() (validations int64, mismatches int64) {
	cg.mu.RLock()
	defer cg.mu.RUnlock()
	return cg.validationCount, cg.mismatchCount
}

// computeFingerprint generates a deterministic fingerprint from the
// current execution environment. Components:
//   - GOOS, GOARCH: platform identity
//   - Hostname: machine identity
//   - Executable path: binary identity
//   - Working directory: deployment location
func (cg *ContextGuard) computeFingerprint() string {
	var parts []string

	parts = append(parts, runtime.GOOS)
	parts = append(parts, runtime.GOARCH)

	if hostname, err := os.Hostname(); err == nil {
		parts = append(parts, hostname)
	}

	if exe, err := os.Executable(); err == nil {
		parts = append(parts, exe)
	}

	if wd, err := os.Getwd(); err == nil {
		parts = append(parts, wd)
	}

	combined := strings.Join(parts, "|")
	h := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(h[:])
}
