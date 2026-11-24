package main

// quantum_posture: Managed agent evidence uses classical Ed25519 signatures and SHA-256 digests.

import (
	"archive/tar"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

type managedAgentSigningMaterial struct {
	keyID        string
	publicKeyHex string
	privateKey   ed25519.PrivateKey
}

type managedAgentLiveReport struct {
	SchemaVersion               string                 `json:"schema_version"`
	Provider                    string                 `json:"provider"`
	PromotionReady              bool                   `json:"promotion_ready"`
	Status                      string                 `json:"status"`
	GeneratedAt                 string                 `json:"generated_at"`
	LastVerified                string                 `json:"last_verified"`
	TestedCommit                string                 `json:"tested_commit"`
	TestedTreeHash              string                 `json:"tested_tree_hash"`
	ArtifactURI                 string                 `json:"artifact_uri"`
	EvidencePackSHA256          string                 `json:"evidence_pack_sha256,omitempty"`
	SignerKeyID                 string                 `json:"signer_key_id"`
	WorkerImageDigest           string                 `json:"worker_image_digest"`
	SkillManifestHash           string                 `json:"skill_manifest_hash"`
	SandboxGrantHash            string                 `json:"sandbox_grant_hash"`
	EnvironmentKeySecretRefHash string                 `json:"environment_key_secret_ref_hash"`
	MCPProfileHashes            map[string]string      `json:"mcp_profile_hashes"`
	ScenarioResults             []managedAgentScenario `json:"scenario_results"`
	Blockers                    []string               `json:"blockers"`
	OfflineVerification         string                 `json:"offline_verification"`
	ClaimLimit                  string                 `json:"claim_limit"`
	Sources                     []string               `json:"sources"`
}

func buildManagedAgentLiveReport(cfg *managedAgentLiveConfig, blockers []string) managedAgentLiveReport {
	return managedAgentLiveReport{
		SchemaVersion:               managedAgentLiveReportVersion,
		Provider:                    cfg.Provider,
		GeneratedAt:                 time.Now().UTC().Format(time.RFC3339),
		LastVerified:                cfg.LastVerified,
		TestedCommit:                cfg.TestedCommit,
		TestedTreeHash:              cfg.TestedTreeHash,
		ArtifactURI:                 cfg.ArtifactURI,
		SignerKeyID:                 cfg.Signer.KeyID,
		WorkerImageDigest:           cfg.Worker.WorkerImageDigest,
		SkillManifestHash:           cfg.Worker.SkillManifestHash,
		SandboxGrantHash:            cfg.Worker.SandboxGrantHash,
		EnvironmentKeySecretRefHash: "sha256:" + sha256Hex([]byte(cfg.Worker.EnvironmentKeySecretRef)),
		MCPProfileHashes: map[string]string{
			"gateway_url_hash":           cfg.MCP.GatewayURLHash,
			"tunnel_domain_hash":         cfg.MCP.TunnelDomainHash,
			"ca_cert_ref_hash":           cfg.MCP.CACertRefHash,
			"allowed_upstream_host_hash": cfg.MCP.AllowedUpstreamHostHash,
			"schema_pin_hash":            cfg.MCP.SchemaPinHash,
		},
		ScenarioResults: cfg.Scenarios,
		Blockers:        blockers,
		ClaimLimit:      "HELM verified claim is limited to the tested customer-controlled worker and HELM MCP Gateway path; Anthropic MCP tunnels remain research-preview.",
		Sources: []string{
			"https://platform.claude.com/docs/en/managed-agents/self-hosted-sandboxes",
			"https://platform.claude.com/docs/en/managed-agents/self-hosted-sandboxes-security",
			"https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/overview",
		},
	}
}

func writeManagedAgentEvidenceDirectory(root string, report managedAgentLiveReport, signer *managedAgentSigningMaterial) error {
	if err := os.RemoveAll(root); err != nil {
		return err
	}
	files := map[string][]byte{}
	addJSON := func(path string, value any) error {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		files[path] = data
		return nil
	}
	if err := addJSON("01_SCORE.json", map[string]any{
		"schema_version":   "managed_agent_live_score.v1",
		"provider":         report.Provider,
		"promotion_ready":  report.PromotionReady,
		"scenario_count":   len(report.ScenarioResults),
		"blocker_count":    len(report.Blockers),
		"last_verified":    report.LastVerified,
		"tested_commit":    report.TestedCommit,
		"tested_tree_hash": report.TestedTreeHash,
	}); err != nil {
		return err
	}
	if err := addJSON("12_REPORTS/claude-managed-agents-live-report.json", report); err != nil {
		return err
	}
	if err := addJSON("02_PROOFGRAPH/proofgraph.json", map[string]any{
		"schema_version": "managed_agent_live_proofgraph.v1",
		"provider":       report.Provider,
		"scenario_count": len(report.ScenarioResults),
		"ready":          report.PromotionReady,
	}); err != nil {
		return err
	}
	if err := addJSON("08_TAPES/managed-agent-scenarios.json", report.ScenarioResults); err != nil {
		return err
	}
	for _, scenario := range report.ScenarioResults {
		decisionHash := "sha256:" + sha256Hex(mustJSONBytes(scenario))
		receipt := map[string]any{
			"receipt_version": "managed_agent_live_scenario_receipt.v1",
			"receipt_id":      scenario.ReceiptID,
			"receipt_hash":    scenario.ReceiptHash,
			"scenario_id":     scenario.ID,
			"effect_type":     scenario.EffectType,
			"verdict":         scenario.Verdict,
			"reason_code":     scenario.ReasonCode,
			"dispatched":      scenario.Dispatched,
			"evidence_ref":    scenario.EvidenceRef,
			"observed_at":     scenario.ObservedAt,
			"decision_hash":   decisionHash,
		}
		if signer != nil {
			signature, err := signer.sign([]byte(decisionHash))
			if err != nil {
				return err
			}
			receipt["signature_algorithm"] = "ed25519"
			receipt["signature_payload"] = "decision_hash"
			receipt["signer_key_id"] = signer.keyID
			receipt["signing_public_key_hex"] = signer.publicKeyHex
			receipt["signature"] = signature
		}
		if err := addJSON("02_PROOFGRAPH/receipts/"+safeEvidenceName(scenario.ID)+".json", receipt); err != nil {
			return err
		}
		if err := addJSON("12_REPORTS/managed-agent-receipts/"+safeEvidenceName(scenario.ID)+".json", scenario); err != nil {
			return err
		}
	}
	files["03_TELEMETRY/worker-retention.txt"] = []byte("worker log retention evidence is referenced by scenario evidence_ref fields\n")
	files["04_EXPORTS/artifact-uri.txt"] = []byte(report.ArtifactURI + "\n")
	files["05_DIFFS/no-source-diff.txt"] = []byte("live evidence pack contains sanitized reports and receipt references only\n")
	files["06_LOGS/retention.txt"] = []byte("retained logs are hash-referenced in the redacted live config\n")
	files["09_SCHEMAS/claude-self-hosted-live-config.schema-ref.txt"] = []byte("protocols/json-schemas/managed-agents/claude_self_hosted_live_config.v1.schema.json\n")
	if signer != nil {
		if err := addJSON("07_ATTESTATIONS/managed-agent-receipt-signer.json", map[string]string{
			"algorithm":      "ed25519",
			"key_id":         signer.keyID,
			"public_key_hex": signer.publicKeyHex,
		}); err != nil {
			return err
		}
	} else {
		files["07_ATTESTATIONS/unsigned.txt"] = []byte("live evidence report was not signed in this run\n")
	}

	entries := make([]map[string]string, 0, len(files))
	for path, data := range files {
		entries = append(entries, map[string]string{"path": path, "sha256": sha256Hex(data)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i]["path"] < entries[j]["path"] })
	indexData, err := json.MarshalIndent(map[string]any{"entries": entries}, "", "  ")
	if err != nil {
		return err
	}
	files["00_INDEX.json"] = indexData

	for path, data := range files {
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0600); err != nil {
			return err
		}
	}
	if _, err := evidencepkg.SealEvidencePack(context.Background(), root, evidencepkg.SealEvidencePackOptions{
		PackID: "managed-agents-" + safeEvidenceName(report.Provider),
	}); err != nil {
		return err
	}
	return nil
}

func archiveManagedAgentEvidence(root, outPath string) error {
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	tw := tar.NewWriter(out)
	defer tw.Close()
	var paths []string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	}); err != nil {
		return err
	}
	sort.Strings(paths)
	for _, rel := range paths {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		hdr := &tar.Header{Name: rel, Size: int64(len(data)), Mode: 0644, ModTime: time.Unix(0, 0), Uid: 0, Gid: 0, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func loadManagedAgentSigningMaterial(keyID string) (*managedAgentSigningMaterial, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return nil, fmt.Errorf("signer.key_id is required")
	}
	keyHex := strings.TrimSpace(os.Getenv("HELM_SIGNING_KEY_HEX"))
	if keyHex == "" {
		return nil, fmt.Errorf("HELM_SIGNING_KEY_HEX is required for --sign")
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid HELM_SIGNING_KEY_HEX: %w", err)
	}
	var seed []byte
	switch len(keyBytes) {
	case ed25519.SeedSize:
		seed = keyBytes
	case ed25519.PrivateKeySize:
		seed = keyBytes[:ed25519.SeedSize]
	default:
		return nil, fmt.Errorf("HELM_SIGNING_KEY_HEX must encode a 32-byte Ed25519 seed or 64-byte private key")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot derive Ed25519 public key")
	}
	return &managedAgentSigningMaterial{
		keyID:        keyID,
		publicKeyHex: hex.EncodeToString(pub),
		privateKey:   priv,
	}, nil
}

func managedAgentSignerPublicKeyHex(signer *managedAgentSigningMaterial) string {
	if signer == nil {
		return ""
	}
	return signer.publicKeyHex
}

func (s *managedAgentSigningMaterial) sign(data []byte) (string, error) {
	if s == nil || len(s.privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("managed-agent signer is not configured")
	}
	return hex.EncodeToString(ed25519.Sign(s.privateKey, data)), nil
}

func signManagedAgentLiveReport(path string, signer *managedAgentSigningMaterial) (map[string]string, error) {
	if signer == nil {
		return nil, fmt.Errorf("managed-agent signer is not configured")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	sig, err := signer.sign(digest[:])
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"algorithm":      "ed25519",
		"key_id":         signer.keyID,
		"public_key_hex": signer.publicKeyHex,
		"report_hash":    hex.EncodeToString(digest[:]),
		"signature":      sig,
	}, nil
}

func promoteManagedAgentRegistry(path string, report managedAgentLiveReport) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var registry map[string]any
	if err := json.Unmarshal(data, &registry); err != nil {
		return err
	}
	adapters, ok := registry["sandbox_adapters"].([]any)
	if !ok {
		return fmt.Errorf("sandbox_adapters missing or invalid")
	}
	found := false
	for _, item := range adapters {
		entry, ok := item.(map[string]any)
		if !ok || entry["name"] != managedAgentVerifiedName {
			continue
		}
		found = true
		entry["tier"] = "verified"
		entry["status"] = "active"
		entry["last_verified"] = report.LastVerified
		entry["evidence_pack"] = map[string]any{
			"artifact_uri":        report.ArtifactURI,
			"sha256":              report.EvidencePackSHA256,
			"signer":              report.SignerKeyID,
			"tested_commit":       report.TestedCommit,
			"tested_tree_hash":    report.TestedTreeHash,
			"worker_image_digest": report.WorkerImageDigest,
			"skill_manifest_hash": report.SkillManifestHash,
			"sandbox_grant_hash":  report.SandboxGrantHash,
			"mcp_profile_hashes":  report.MCPProfileHashes,
		}
		entry["notes"] = report.ClaimLimit
	}
	if !found {
		return fmt.Errorf("%q entry not found", managedAgentVerifiedName)
	}
	out, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0600)
}

func writeManagedAgentJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0600)
}

func safeEvidenceName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "scenario"
	}
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", " ", "-")
	return replacer.Replace(value)
}

func mustJSONBytes(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}
