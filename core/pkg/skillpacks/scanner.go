package skillpacks

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

func ScanPath(path string) (ScanResult, error) {
	pack, err := Load(path)
	if err != nil {
		return ScanResult{}, err
	}
	return Scan(pack)
}

func Scan(pack SkillPack) (ScanResult, error) {
	contentHash := HashBytes([]byte(pack.SkillMD))
	result := ScanResult{
		SkillID:          pack.Manifest.ID,
		Verdict:          VerdictAllow,
		SkillContentHash: contentHash,
		Findings:         []Finding{},
	}
	add := func(code, severity, message, path string) {
		result.Findings = append(result.Findings, Finding{Code: code, Severity: severity, Message: message, Path: path})
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
	if err := VerifyPublisherSignature(pack, nil); err != nil {
		if pack.Manifest.Status == StatusVerified {
			result.Verdict = VerdictDeny
			result.ReasonCode = "ERR_SKILL_SIGNATURE_INVALID"
		} else {
			setEscalate(&result, "ERR_SKILL_SIGNATURE_INVALID")
		}
		add("ERR_SKILL_SIGNATURE_INVALID", "HIGH", err.Error(), "skillpack.json")
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
		add("ERR_SKILL_SIGNATURE_MISSING", "MEDIUM", "skill signature reference is required for verified status", "skillpack.json")
	}
	if !pack.Manifest.PermissionsDoNotGrantTools {
		setEscalate(&result, "ERR_SKILL_AUTHORITY_BOUNDARY_MISSING")
		add("ERR_SKILL_AUTHORITY_BOUNDARY_MISSING", "HIGH", "manifest must declare that skills do not grant tool permissions", "skillpack.json")
	}
	if pack.Root != "" {
		if repoRoot, err := findRepoRoot(pack.Root); err == nil {
			if err := ValidatePolicyFile(repoRoot, pack.Manifest.PolicyRef); err != nil {
				setEscalate(&result, "ERR_SKILL_POLICY_INVALID")
				add("ERR_SKILL_POLICY_INVALID", "HIGH", err.Error(), pack.Manifest.PolicyRef)
			}
		}
		if err := scanBundleFiles(pack.Root, add); err != nil {
			result.Verdict = VerdictDeny
			result.ReasonCode = err.Error()
		}
		for _, script := range pack.Manifest.Scripts {
			if script != "" {
				setEscalate(&result, "ERR_SKILL_SCRIPT_REVIEW_REQUIRED")
				add("ERR_SKILL_SCRIPT_REVIEW_REQUIRED", "MEDIUM", "executable scripts require review", script)
			}
		}
	}
	result.Attestation = ScanAttestation{
		Type:             "SKILL_SCAN_ATTESTATION",
		SkillID:          result.SkillID,
		Verdict:          result.Verdict,
		ReasonCode:       result.ReasonCode,
		SkillContentHash: contentHash,
		CreatedAt:        time.Now().UTC(),
	}
	result.Attestation.ID = "attestation:" + hashCanonical(result.Attestation)
	return result, nil
}

func scanBundleFiles(root string, add func(code, severity, message, path string)) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if d.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			resolved := target
			if !filepath.IsAbs(resolved) {
				resolved = filepath.Clean(filepath.Join(filepath.Dir(path), target))
			}
			rootClean := filepath.Clean(root)
			if !strings.HasPrefix(resolved, rootClean+string(filepath.Separator)) && resolved != rootClean {
				add("ERR_SKILL_PATH_ESCAPE", "HIGH", "symlink escapes skill root", rel)
				return errors.New("ERR_SKILL_PATH_ESCAPE")
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > 0 && info.Size() <= 1<<20 {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), "\x00") || !utf8.Valid(data) {
				add("ERR_SKILL_OPAQUE_BINARY", "MEDIUM", "opaque binary payload requires provenance review", rel)
				return fmt.Errorf("ERR_SKILL_OPAQUE_BINARY")
			}
		}
		return nil
	})
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
