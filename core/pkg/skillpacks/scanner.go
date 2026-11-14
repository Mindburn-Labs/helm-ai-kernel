package skillpacks

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/threatscan"
)

func ScanPath(path string) (ScanResult, error) {
	pack, err := Load(path)
	if err != nil {
		return ScanResult{}, err
	}
	return Scan(pack)
}

// Scan judges a pack under the rules and the first-party manifest compiled
// into this binary. It returns ALLOW only for a pack whose files are the ones
// the binary pins; nothing a pack says about itself can earn that.
func Scan(pack SkillPack) (ScanResult, error) {
	return scanPack(pack, loadKernelFirstPartyTrust())
}

// scanPack runs the SkillPack checks. trust is the publisher trust material:
// Scan, and through it the install path, passes the manifest compiled into the
// binary, and the scan is then the only gate. ProjectionLifecycle passes nil
// because it binds trust to a decision its configured verifier signs: the scan
// then applies the prompt and manifest rules only, and its result says the
// publisher was not checked here.
func scanPack(pack SkillPack, trust *firstPartyTrust) (ScanResult, error) {
	contentHash := HashBytes([]byte(pack.SkillMD))
	result := ScanResult{
		SkillID:          pack.Manifest.ID,
		Verdict:          VerdictAllow,
		SkillContentHash: contentHash,
		Policy:           loadKernelFirstPartyTrust().scanPolicy(),
		Findings:         []Finding{},
	}
	add := func(code, severity, message, path string) {
		result.Findings = append(result.Findings, Finding{Code: code, Severity: severity, Message: message, Path: path})
	}
	deny := func(code, severity, message, path string) {
		result.Verdict = VerdictDeny
		result.ReasonCode = code
		add(code, severity, message, path)
	}
	lower := strings.ToLower(pack.SkillMD + "\n" + pack.Manifest.Description + "\n" + strings.Join(pack.Manifest.Hooks, "\n") + "\n" + strings.Join(pack.Manifest.RequestedMCPTools, "\n"))
	denyPatterns := map[string]string{
		"ignore all helm":              "ERR_SKILL_POLICY_BYPASS_ATTEMPT",
		"ignore helm policy":           "ERR_SKILL_POLICY_BYPASS_ATTEMPT",
		"bypass helm":                  "ERR_SKILL_POLICY_BYPASS_ATTEMPT",
		"bypass policy":                "ERR_SKILL_POLICY_BYPASS_ATTEMPT",
		"read ~/.ssh":                  "ERR_SKILL_SECRET_EXFIL_ATTEMPT",
		"read all secrets":             "ERR_SKILL_SECRET_EXFIL_ATTEMPT",
		"exfiltrate":                   "ERR_SKILL_SECRET_EXFIL_ATTEMPT",
		"steal secrets":                "ERR_SKILL_SECRET_EXFIL_ATTEMPT",
		"ignore previous instructions": "ERR_SKILL_PROMPT_INJECTION_METADATA",
		"auto approve shell":           "ERR_SKILL_HOOK_AUTO_APPROVE_ATTEMPT",
		"permissionrequest allow":      "ERR_SKILL_HOOK_AUTO_APPROVE_ATTEMPT",
	}
	for needle, code := range denyPatterns {
		if strings.Contains(lower, needle) {
			result.Verdict = VerdictDeny
			result.ReasonCode = code
			add(code, "HIGH", "skill attempts to bypass HELM policy or exfiltrate secrets", "SKILL.md")
			break
		}
	}
	if result.Verdict != VerdictDeny {
		escalate := map[string]string{
			"global install":         "ERR_GLOBAL_SKILL_INSTALL_DENIED",
			"--scope user":           "ERR_GLOBAL_SKILL_INSTALL_DENIED",
			"install globally":       "ERR_GLOBAL_SKILL_INSTALL_DENIED",
			"auto-enable mcp":        "ERR_SKILL_MCP_AUTO_ENABLE_ATTEMPT",
			"enable side-effect mcp": "ERR_SKILL_MCP_AUTO_ENABLE_ATTEMPT",
			"side-effect tool":       "ERR_SKILL_MCP_SIDE_EFFECT_REVIEW_REQUIRED",
		}
		for needle, code := range escalate {
			if strings.Contains(lower, needle) {
				result.Verdict = VerdictEscalate
				result.ReasonCode = code
				add(code, "MEDIUM", "skill requests elevated scope or side-effect tooling review", "SKILL.md")
				break
			}
		}
	}
	if pack.Manifest.ID == "" || pack.Manifest.Name == "" || pack.Manifest.Description == "" {
		setEscalate(&result, "ERR_SKILL_SCHEMA_INVALID")
		add("ERR_SKILL_SCHEMA_INVALID", "HIGH", "skill manifest requires id, name, and description", "skillpack.json")
	}
	if err := ValidateManifest(pack.Manifest, []byte(pack.SkillMD)); err != nil {
		setEscalate(&result, "ERR_SKILL_SCHEMA_INVALID")
		add("ERR_SKILL_SCHEMA_INVALID", "HIGH", err.Error(), "skillpack.json")
	}
	// One read of the pack directory feeds the file checks, the content digest
	// and the comparison with what was loaded.
	var tree *packTree
	if pack.Root != "" {
		read, err := readPackTree(pack.Root)
		if err != nil {
			read = packTree{hazard: &Finding{Code: "ERR_SKILL_BUNDLE_UNREADABLE", Severity: "HIGH", Message: err.Error()}}
		}
		tree = &read
	}
	result.PublisherVerification = checkPublisher(pack, tree, trust)
	switch publisher := result.PublisherVerification; {
	case publisher.State == PublisherNotChecked:
	case publisher.State == PublisherFirstPartyMismatch:
		deny("ERR_SKILL_FIRST_PARTY_DIGEST_MISMATCH", "HIGH", publisher.Reason, "")
	case publisher.State != PublisherFirstParty && pack.Manifest.Status == StatusVerified:
		// The manifest claims a status only a publisher check can give.
		deny("ERR_SKILL_VERIFIED_CLAIM_UNPROVEN", "HIGH", "manifest declares status \"verified\", and "+publisher.Reason, "skillpack.json")
	case publisher.State != PublisherFirstParty:
		setEscalate(&result, "ERR_SKILL_SIGNATURE_UNVERIFIED")
		add("ERR_SKILL_SIGNATURE_UNVERIFIED", "HIGH", publisher.Reason, "skillpack.json")
	case pack.Manifest.Status != StatusVerified:
		setEscalate(&result, "ERR_SKILL_STATUS_REVIEW_REQUIRED")
		add("ERR_SKILL_STATUS_REVIEW_REQUIRED", "MEDIUM", fmt.Sprintf("first-party pack declares status %q; only a verified pack installs without review", pack.Manifest.Status), "skillpack.json")
	}
	if trust != nil {
		// Where this scan is the gate, instructions that run commands or fetch
		// from outside need a reviewer even in a first-party pack. The
		// projection lifecycle keeps the rules it shipped with: services
		// outside this repository run it, and its verifier decides.
		for _, signal := range executionSignals(pack.SkillMD) {
			setEscalate(&result, signal.code)
			add(signal.code, "HIGH", signal.message, "SKILL.md")
		}
	}
	if pack.Manifest.ScopeDefault == ScopeGlobal {
		setEscalate(&result, "ERR_GLOBAL_SKILL_INSTALL_DENIED")
		add("ERR_GLOBAL_SKILL_INSTALL_DENIED", "HIGH", "global skill install is denied by default", "skillpack.json")
	}
	if pack.Manifest.LicenseSPDX == "" {
		setEscalate(&result, "ERR_SKILL_LICENSE_UNVERIFIED")
		add("ERR_SKILL_LICENSE_UNVERIFIED", "MEDIUM", "skill license must be verified before promotion", "skillpack.json")
	}
	if pack.Manifest.SignatureRef == "" {
		setEscalate(&result, "ERR_SKILL_SIGNATURE_MISSING")
		add("ERR_SKILL_SIGNATURE_MISSING", "MEDIUM", "manifest names no signature_ref", "skillpack.json")
	}
	if !pack.Manifest.PermissionsDoNotGrantTools {
		setEscalate(&result, "ERR_SKILL_AUTHORITY_BOUNDARY_MISSING")
		add("ERR_SKILL_AUTHORITY_BOUNDARY_MISSING", "HIGH", "manifest must declare that skills do not grant tool permissions", "skillpack.json")
	}
	if tree != nil {
		if hazard := tree.hazard; hazard != nil {
			deny(hazard.Code, hazard.Severity, hazard.Message, hazard.Path)
		}
		for _, script := range pack.Manifest.Scripts {
			if script != "" {
				setEscalate(&result, "ERR_SKILL_SCRIPT_REVIEW_REQUIRED")
				add("ERR_SKILL_SCRIPT_REVIEW_REQUIRED", "MEDIUM", "executable scripts require review", script)
			}
		}
	}
	result.Attestation = ScanAttestation{
		Type:              "SKILL_SCAN_ATTESTATION",
		SkillID:           result.SkillID,
		Verdict:           result.Verdict,
		ReasonCode:        result.ReasonCode,
		SkillContentHash:  contentHash,
		PublisherState:    result.PublisherVerification.State,
		PackContentDigest: result.PublisherVerification.ContentDigest,
		PolicyHash:        result.Policy.Hash,
		CreatedAt:         time.Now().UTC(),
	}
	result.Attestation.ID = "attestation:" + hashCanonical(result.Attestation)
	return result, nil
}

var loadThreatScanner = sync.OnceValue(func() *threatscan.Scanner { return threatscan.New() })

type executionSignal struct{ code, message string }

// executionSignals reports instructions that run commands or fetch from
// outside the pack, such as a download piped into a shell. It reuses the
// kernel's threat scanner, so a skill and a tool call are read by the same
// rules; the two reason codes are that scanner's two classes.
func executionSignals(skillMD string) []executionSignal {
	scan := loadThreatScanner().ScanInput(skillMD, contracts.SourceChannelUnknown, contracts.InputTrustExternalUntrusted)
	var signals []executionSignal
	for _, finding := range scan.Findings {
		var code string
		switch finding.Class {
		case contracts.ThreatClassCommandExecution:
			code = "ERR_SKILL_COMMAND_EXECUTION_REVIEW_REQUIRED"
		case contracts.ThreatClassSuspiciousFetch:
			code = "ERR_SKILL_EXTERNAL_FETCH_REVIEW_REQUIRED"
		default:
			continue
		}
		signals = append(signals, executionSignal{code: code, message: fmt.Sprintf("instructions match threat rule %s (%s): %s",
			finding.RuleID, finding.Class, strings.Join(finding.MatchedTokens, ", "))})
	}
	return signals
}

func setEscalate(result *ScanResult, code string) {
	if result.Verdict == VerdictDeny {
		return
	}
	result.Verdict = VerdictEscalate
	if result.ReasonCode == "" {
		result.ReasonCode = code
	}
}
