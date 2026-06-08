package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	errSandboxSecurityReceiptInvalid = errors.New("sandbox security receipt invalid")
	errSandboxCredentialMaterial     = errors.New("sandbox security receipt credential material detected")
)

// SandboxSecurityReceipt captures the security posture needed to trust a PoC or
// verifier run independently of the sandbox execution transcript.
type SandboxSecurityReceipt struct {
	ReceiptID            string            `json:"receipt_id"`
	ExecutionID          string            `json:"execution_id"`
	SpecHash             string            `json:"spec_hash"`
	SandboxConfigHash    string            `json:"sandbox_config_hash"`
	ImageDigest          string            `json:"image_digest"`
	AllowedEgress        []string          `json:"allowed_egress,omitempty"`
	AllowedEgressHash    string            `json:"allowed_egress_hash"`
	MountedPathsHash     string            `json:"mounted_paths_hash"`
	SecretScanResult     SecretScanResult  `json:"secret_scan_result"`
	BuildDigest          string            `json:"build_digest"`
	PoCTranscriptHash    string            `json:"poc_transcript_hash"`
	VerifierVerdictHash  string            `json:"verifier_verdict_hash"`
	NoCredentialMaterial bool              `json:"no_credential_material"`
	Metadata             map[string]string `json:"metadata,omitempty"`
	CreatedAt            time.Time         `json:"created_at"`
}

// SecretScanResult records the verifier's credential-material scan without
// storing any secret value.
type SecretScanResult struct {
	Result    string    `json:"result"`
	Hash      string    `json:"hash"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

// NewSandboxSecurityReceipt derives the receipt hashes from a sandbox execution
// receipt and validates the minimum HELM security posture.
func NewSandboxSecurityReceipt(exec *ExecutionReceipt, buildDigest, pocTranscriptHash, verifierVerdictHash, secretScanHash string, noCredentialMaterial bool) (*SandboxSecurityReceipt, error) {
	if exec == nil {
		return nil, fmt.Errorf("%w: execution receipt is required", errSandboxSecurityReceiptInvalid)
	}
	now := time.Now().UTC()
	allowedEgress := append([]string(nil), exec.Spec.Network.EgressAllowlist...)
	sort.Strings(allowedEgress)
	receipt := &SandboxSecurityReceipt{
		ReceiptID:            "sandbox-security:" + exec.ExecutionID,
		ExecutionID:          exec.ExecutionID,
		SpecHash:             hashJSON(exec.Spec),
		SandboxConfigHash:    hashJSON(sandboxConfigForHash(exec.Spec)),
		ImageDigest:          exec.ImageDigest,
		AllowedEgress:        allowedEgress,
		AllowedEgressHash:    hashJSON(allowedEgress),
		MountedPathsHash:     hashJSON(sortedMounts(exec.Spec.Mounts)),
		SecretScanResult:     SecretScanResult{Result: secretScanResult(noCredentialMaterial), Hash: secretScanHash, CheckedAt: now},
		BuildDigest:          buildDigest,
		PoCTranscriptHash:    pocTranscriptHash,
		VerifierVerdictHash:  verifierVerdictHash,
		NoCredentialMaterial: noCredentialMaterial,
		CreatedAt:            now,
	}
	if err := ValidateSandboxSecurityReceipt(exec, receipt); err != nil {
		return nil, err
	}
	return receipt, nil
}

// ValidateSandboxSecurityReceipt proves the receipt still matches its execution
// envelope and that the sandbox had no broad egress or credential material.
func ValidateSandboxSecurityReceipt(exec *ExecutionReceipt, receipt *SandboxSecurityReceipt) error {
	if exec == nil {
		return fmt.Errorf("%w: execution receipt is required", errSandboxSecurityReceiptInvalid)
	}
	if receipt == nil {
		return fmt.Errorf("%w: security receipt is required", errSandboxSecurityReceiptInvalid)
	}
	if receipt.ExecutionID == "" || receipt.ExecutionID != exec.ExecutionID {
		return fmt.Errorf("%w: execution_id mismatch", errSandboxSecurityReceiptInvalid)
	}
	if !imagePinnedByDigest(exec.Spec.Image) {
		return fmt.Errorf("%w: sandbox image must be pinned by digest", errSandboxSecurityReceiptInvalid)
	}
	if receipt.ImageDigest == "" || !strings.Contains(exec.Spec.Image, receipt.ImageDigest) {
		return fmt.Errorf("%w: image_digest must match pinned image", errSandboxSecurityReceiptInvalid)
	}
	if receipt.SpecHash != hashJSON(exec.Spec) {
		return fmt.Errorf("%w: spec_hash mismatch", errSandboxSecurityReceiptInvalid)
	}
	if receipt.SandboxConfigHash != hashJSON(sandboxConfigForHash(exec.Spec)) {
		return fmt.Errorf("%w: sandbox_config_hash mismatch", errSandboxSecurityReceiptInvalid)
	}
	if receipt.MountedPathsHash != hashJSON(sortedMounts(exec.Spec.Mounts)) {
		return fmt.Errorf("%w: mounted_paths_hash mismatch", errSandboxSecurityReceiptInvalid)
	}
	allowedEgress := append([]string(nil), exec.Spec.Network.EgressAllowlist...)
	sort.Strings(allowedEgress)
	if receipt.AllowedEgressHash != hashJSON(allowedEgress) {
		return fmt.Errorf("%w: allowed_egress_hash mismatch", errSandboxSecurityReceiptInvalid)
	}
	if !exec.Spec.Network.Disabled && len(exec.Spec.Network.EgressAllowlist) == 0 {
		return fmt.Errorf("%w: network must be disabled or egress allowlisted", errSandboxSecurityReceiptInvalid)
	}
	if !receipt.NoCredentialMaterial || !strings.EqualFold(receipt.SecretScanResult.Result, "clean") || receipt.SecretScanResult.Hash == "" {
		return fmt.Errorf("%w: clean secret scan is required", errSandboxSecurityReceiptInvalid)
	}
	if sandboxSpecHasCredentialMaterial(exec.Spec) {
		return errSandboxCredentialMaterial
	}
	if receipt.BuildDigest == "" || receipt.PoCTranscriptHash == "" || receipt.VerifierVerdictHash == "" {
		return fmt.Errorf("%w: build_digest, poc_transcript_hash, and verifier_verdict_hash are required", errSandboxSecurityReceiptInvalid)
	}
	return nil
}

func hashJSON(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func imagePinnedByDigest(image string) bool {
	return strings.Contains(image, "@sha256:")
}

func secretScanResult(clean bool) string {
	if clean {
		return "clean"
	}
	return "failed"
}

func sandboxConfigForHash(spec SandboxSpec) any {
	return struct {
		Image        string            `json:"image"`
		Command      []string          `json:"command"`
		Args         []string          `json:"args"`
		Mounts       []Mount           `json:"mounts"`
		Limits       ResourceLimits    `json:"limits"`
		Network      NetworkPolicy     `json:"network"`
		WorkDir      string            `json:"workdir"`
		RuntimeClass string            `json:"runtime_class,omitempty"`
		Labels       map[string]string `json:"labels,omitempty"`
	}{
		Image:        spec.Image,
		Command:      append([]string(nil), spec.Command...),
		Args:         append([]string(nil), spec.Args...),
		Mounts:       sortedMounts(spec.Mounts),
		Limits:       spec.Limits,
		Network:      spec.Network,
		WorkDir:      spec.WorkDir,
		RuntimeClass: spec.RuntimeClass,
		Labels:       spec.Labels,
	}
}

func sortedMounts(mounts []Mount) []Mount {
	out := append([]Mount(nil), mounts...)
	sort.Slice(out, func(i, j int) bool {
		left := out[i].Source + "\x00" + out[i].Target
		right := out[j].Source + "\x00" + out[j].Target
		if left == right {
			return !out[i].ReadOnly && out[j].ReadOnly
		}
		return left < right
	})
	return out
}

func sandboxSpecHasCredentialMaterial(spec SandboxSpec) bool {
	for key, value := range spec.Env {
		lowerKey := strings.ToLower(key)
		lowerValue := strings.ToLower(value)
		if secretLike(lowerKey) || strings.Contains(lowerValue, "-----begin ") {
			return true
		}
	}
	for _, mount := range spec.Mounts {
		if secretLike(strings.ToLower(mount.Source)) || secretLike(strings.ToLower(mount.Target)) {
			return true
		}
	}
	return false
}

func secretLike(value string) bool {
	needles := []string{
		"secret", "token", "password", "credential", "api_key", "apikey", "private_key",
		".ssh", ".aws", ".azure", ".config/gcloud", ".kube", ".env", ".pem", ".key",
	}
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
