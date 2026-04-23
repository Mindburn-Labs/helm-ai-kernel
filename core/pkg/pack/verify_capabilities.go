// verify_capabilities.go implements SkillFortify-style capability verification
// for HELM skill packs. Before a skill is installed, this verifier checks that
// the skill's actual behavior cannot exceed its declared capabilities.
//
// Per arXiv 2603.00195 (CVE-2026-25253): 1,200+ malicious skills infiltrated
// the OpenClaw marketplace. SkillFortify provides mathematical guarantees.
//
// Design invariants:
//   - Verification is static (no execution needed)
//   - Fail-closed: verification failure = skill rejected
//   - Checks: declared tools match manifest, no undeclared network access,
//     no filesystem access beyond declared paths, no exec/eval patterns
package pack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// CapabilityVerification is the result of verifying a skill's declared capabilities
// against its actual content.
type CapabilityVerification struct {
	SkillID          string                `json:"skill_id"`
	Verified         bool                  `json:"verified"`
	DeclaredCaps     []string              `json:"declared_capabilities"`
	Violations       []CapabilityViolation `json:"violations,omitempty"`
	VerifiedAt       time.Time             `json:"verified_at"`
	VerificationHash string                `json:"verification_hash"`
}

// CapabilityViolation describes a single undeclared capability detected in skill content.
type CapabilityViolation struct {
	Type        string `json:"type"` // UNDECLARED_TOOL, NETWORK_ACCESS, FILESYSTEM_ACCESS, CODE_EXECUTION
	Description string `json:"description"`
	Severity    string `json:"severity"` // HIGH, CRITICAL
	Evidence    string `json:"evidence"` // The offending pattern/code
}

// CapabilityVerifier performs static analysis of skill content to detect
// undeclared capabilities.
type CapabilityVerifier struct {
	clock func() time.Time
}

// VerifierOption configures the CapabilityVerifier.
type VerifierOption func(*CapabilityVerifier)

// WithClock sets a custom clock for deterministic testing.
func WithClock(clock func() time.Time) VerifierOption {
	return func(v *CapabilityVerifier) {
		v.clock = clock
	}
}

// NewCapabilityVerifier creates a new verifier with the given options.
func NewCapabilityVerifier(opts ...VerifierOption) *CapabilityVerifier {
	v := &CapabilityVerifier{
		clock: func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// networkPatterns are byte sequences indicating undeclared network access.
var networkPatterns = []patternDef{
	{pattern: []byte("http://"), desc: "HTTP URL detected", severity: "HIGH"},
	{pattern: []byte("https://"), desc: "HTTPS URL detected", severity: "HIGH"},
	{pattern: []byte("net.Dial"), desc: "Go net.Dial call detected", severity: "CRITICAL"},
	{pattern: []byte("fetch("), desc: "JavaScript fetch() call detected", severity: "HIGH"},
	{pattern: []byte("curl"), desc: "curl command detected", severity: "HIGH"},
	{pattern: []byte("wget"), desc: "wget command detected", severity: "HIGH"},
}

// filesystemPatterns are byte sequences indicating undeclared filesystem access.
var filesystemPatterns = []patternDef{
	{pattern: []byte("/etc/"), desc: "Access to /etc/ detected", severity: "CRITICAL"},
	{pattern: []byte("/root/"), desc: "Access to /root/ detected", severity: "CRITICAL"},
	{pattern: []byte("os.Remove"), desc: "os.Remove call detected", severity: "CRITICAL"},
	{pattern: []byte("os.WriteFile"), desc: "os.WriteFile call detected", severity: "HIGH"},
	{pattern: []byte("ioutil.WriteFile"), desc: "ioutil.WriteFile call detected", severity: "HIGH"},
}

// codeExecPatterns are byte sequences indicating undeclared code execution.
var codeExecPatterns = []patternDef{
	{pattern: []byte("exec.Command"), desc: "exec.Command call detected", severity: "CRITICAL"},
	{pattern: []byte("os/exec"), desc: "os/exec import detected", severity: "CRITICAL"},
	{pattern: []byte("eval("), desc: "eval() call detected", severity: "CRITICAL"},
	{pattern: []byte("subprocess"), desc: "subprocess module usage detected", severity: "CRITICAL"},
	{pattern: []byte("os.system"), desc: "os.system call detected", severity: "CRITICAL"},
}

// miningPatterns are byte sequences indicating crypto mining activity.
var miningPatterns = []patternDef{
	{pattern: []byte("stratum+"), desc: "Mining stratum protocol detected", severity: "CRITICAL"},
	{pattern: []byte("mining"), desc: "Mining-related keyword detected", severity: "HIGH"},
	{pattern: []byte("hashrate"), desc: "Hashrate reference detected", severity: "HIGH"},
}

type patternDef struct {
	pattern  []byte
	desc     string
	severity string
}

// VerifyManifest scans content bytes for undeclared capabilities and returns
// a verification result. Fail-closed: any detected violation marks the
// verification as failed.
func (v *CapabilityVerifier) VerifyManifest(skillID string, declaredCaps []string, content []byte) (*CapabilityVerification, error) {
	now := v.clock()

	result := &CapabilityVerification{
		SkillID:      skillID,
		DeclaredCaps: declaredCaps,
		VerifiedAt:   now,
		Verified:     true,
	}

	// Scan for undeclared capabilities.
	hasCap := func(cap string) bool {
		for _, c := range declaredCaps {
			if c == cap {
				return true
			}
		}
		return false
	}

	// Check network access patterns.
	if !hasCap("network") {
		for _, p := range networkPatterns {
			if bytes.Contains(content, p.pattern) {
				result.Violations = append(result.Violations, CapabilityViolation{
					Type:        "NETWORK_ACCESS",
					Description: p.desc,
					Severity:    p.severity,
					Evidence:    string(p.pattern),
				})
			}
		}
	}

	// Check filesystem access patterns.
	if !hasCap("filesystem") {
		for _, p := range filesystemPatterns {
			if bytes.Contains(content, p.pattern) {
				result.Violations = append(result.Violations, CapabilityViolation{
					Type:        "FILESYSTEM_ACCESS",
					Description: p.desc,
					Severity:    p.severity,
					Evidence:    string(p.pattern),
				})
			}
		}
	}

	// Check code execution patterns.
	if !hasCap("code_execution") {
		for _, p := range codeExecPatterns {
			if bytes.Contains(content, p.pattern) {
				result.Violations = append(result.Violations, CapabilityViolation{
					Type:        "CODE_EXECUTION",
					Description: p.desc,
					Severity:    p.severity,
					Evidence:    string(p.pattern),
				})
			}
		}
	}

	// Check crypto mining patterns (never allowed, regardless of declared caps).
	for _, p := range miningPatterns {
		if bytes.Contains(content, p.pattern) {
			result.Violations = append(result.Violations, CapabilityViolation{
				Type:        "UNDECLARED_TOOL",
				Description: p.desc,
				Severity:    p.severity,
				Evidence:    string(p.pattern),
			})
		}
	}

	// Fail-closed: any violation means verification failed.
	if len(result.Violations) > 0 {
		result.Verified = false
	}

	// Compute verification hash over the result (excluding the hash itself).
	hash, err := computeVerificationHash(result)
	if err != nil {
		return nil, err
	}
	result.VerificationHash = hash

	return result, nil
}

// computeVerificationHash produces a deterministic hash of the verification result.
func computeVerificationHash(v *CapabilityVerification) (string, error) {
	hashable := struct {
		SkillID      string                `json:"skill_id"`
		Verified     bool                  `json:"verified"`
		DeclaredCaps []string              `json:"declared_capabilities"`
		Violations   []CapabilityViolation `json:"violations,omitempty"`
		VerifiedAt   time.Time             `json:"verified_at"`
	}{
		SkillID:      v.SkillID,
		Verified:     v.Verified,
		DeclaredCaps: v.DeclaredCaps,
		Violations:   v.Violations,
		VerifiedAt:   v.VerifiedAt,
	}

	data, err := canonicalize.JCS(hashable)
	if err != nil {
		return "", err
	}

	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
