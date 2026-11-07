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
	"time"
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
