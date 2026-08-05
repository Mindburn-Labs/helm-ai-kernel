package riskscan

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/executor"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/riskenvelope"
)

const (
	riskScanEvidencePackFile = "evidence-pack.json"
	riskScanEnvelopeFile     = "risk-envelope.json"
	riskScanPreviewDir       = "previews"
	riskScanActorID          = "helm-ai-kernel/scan"
	riskScanEffectType       = "risk-scan"
	// ponytail: 16 MiB per artifact bounds offline verification; make the limit configurable only if legitimate scan exports exceed it.
	maxRiskScanArtifactBytes = 16 << 20
)

// EvidencePackVerification reports only whether the exported local artifacts
// still match the current EvidencePack contract. It is not execution,
// authorization, provenance, or live-posture verification.
type EvidencePackVerification struct {
	Verified   bool     `json:"verified"`
	PackID     string   `json:"pack_id,omitempty"`
	EnvelopeID string   `json:"envelope_id,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

// WriteEvidencePack exports a scan as a transport tar containing the current
// contracts.EvidencePack plus the anonymized artifacts it hashes. The tar adds
// no independent manifest, seal, or trust format.
func WriteEvidencePack(path string, envelope riskenvelope.RiskEnvelope, previews map[string][]byte) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("evidence pack path is required")
	}

	entries, pack, err := buildEvidencePack(envelope, previews)
	if err != nil {
		return err
	}
	if issues := executor.ValidateEvidencePack(pack); len(issues) > 0 {
		return fmt.Errorf("validate evidence pack: %s", strings.Join(issues, "; "))
	}
	packJSON, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal evidence pack: %w", err)
	}
	entries[riskScanEvidencePackFile] = append(packJSON, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create evidence pack directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".risk-scan-evidence-*")
	if err != nil {
		return fmt.Errorf("create evidence pack: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if err := writeRiskScanTar(temp, entries); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close evidence pack: %w", err)
	}
	if err := os.Chmod(tempPath, 0o600); err != nil {
		return fmt.Errorf("protect evidence pack: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("publish evidence pack: %w", err)
	}
	return nil
}

func buildEvidencePack(envelope riskenvelope.RiskEnvelope, previews map[string][]byte) (map[string][]byte, *contracts.EvidencePack, error) {
	envelopeJSON, err := EnvelopeJSON(envelope)
	if err != nil {
		return nil, nil, fmt.Errorf("build risk envelope: %w", err)
	}
	envelopeHash := riskenvelope.SHA256Ref(envelopeJSON)
	entries := map[string][]byte{riskScanEnvelopeFile: envelopeJSON}
	artifacts := []contracts.ParsedArtifact{{
		ArtifactID: "risk-envelope",
		Type:       "risk-envelope",
		Hash:       envelopeHash,
		URIRef:     riskScanEnvelopeFile,
	}}

	previewNames := make([]string, 0, len(previews))
	for name := range previews {
		previewNames = append(previewNames, name)
	}
	sort.Strings(previewNames)
	seenPreviews := make(map[string]struct{}, len(previewNames))
	for _, name := range previewNames {
		cleanName, err := cleanPreviewName(name)
		if err != nil {
			return nil, nil, err
		}
		if _, exists := seenPreviews[cleanName]; exists {
			return nil, nil, fmt.Errorf("duplicate scan preview %q", cleanName)
		}
		seenPreviews[cleanName] = struct{}{}
		payload := previews[name]
		if len(payload) == 0 || len(payload) > maxRiskScanArtifactBytes {
			return nil, nil, fmt.Errorf("scan preview %q has invalid size", cleanName)
		}
		rel := filepath.ToSlash(filepath.Join(riskScanPreviewDir, cleanName))
		entries[rel] = payload
		artifacts = append(artifacts, contracts.ParsedArtifact{
			ArtifactID: "preview:" + cleanName,
			Type:       "risk-scan-preview",
			Hash:       riskenvelope.SHA256Ref(payload),
			URIRef:     rel,
		})
	}

	producer := executor.NewEvidencePackProducer("local-risk-scan")
	pack, err := producer.Produce(context.Background(), &executor.EvidencePackInput{
		ActorID:             riskScanActorID,
		ActorType:           "module",
		SessionID:           envelope.EnvelopeID,
		DecisionID:          "risk-scan:" + envelope.EnvelopeID,
		PolicyVersion:       riskenvelope.SchemaVersion,
		EvaluationGraphHash: envelope.SourcePackHash,
		EffectID:            "risk-scan:" + envelope.EnvelopeID,
		EffectType:          riskScanEffectType,
		EffectPayloadHash:   envelopeHash,
		Classification:      "reversible",
		ResultHash:          envelopeHash,
		Status:              "success",
		StartedAt:           envelope.GeneratedAt,
		CompletedAt:         envelope.GeneratedAt,
		BundledArtifacts:    artifacts,
		VerificationScopes: []contracts.VerificationScope{{
			VerificationScopeID: "risk-scan-local-artifact-integrity",
			SubjectHash:         envelopeHash,
			ChecksPerformed:     []string{"evidence-pack hash validation", "bundled artifact hash validation", "risk envelope validation"},
			KnownLimits:         []string{"No runtime authorization, governed execution, provenance, or live-posture claim is verified."},
			PolicyHash:          envelope.SourcePackHash,
			CreatedAt:           envelope.GeneratedAt,
		}},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("produce evidence pack: %w", err)
	}
	return entries, pack, nil
}

func cleanPreviewName(name string) (string, error) {
	name = strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(name)), "preview/")
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, ":") || filepath.Base(name) != name {
		return "", fmt.Errorf("invalid scan preview path %q", name)
	}
	ext := strings.ToLower(filepath.Ext(name))
	if ext != ".md" && ext != ".html" {
		return "", fmt.Errorf("scan preview path must end in .md or .html: %q", name)
	}
	return name, nil
}

func writeRiskScanTar(file *os.File, entries map[string][]byte) error {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	writer := tar.NewWriter(file)
	for _, name := range names {
		data := entries[name]
		if len(data) > maxRiskScanArtifactBytes {
			writer.Close()
			return fmt.Errorf("evidence pack entry %q exceeds size limit", name)
		}
		if err := writer.WriteHeader(&tar.Header{
			Name:    name,
			Mode:    0o600,
			Size:    int64(len(data)),
			ModTime: time.Unix(0, 0),
		}); err != nil {
			writer.Close()
			return fmt.Errorf("write evidence pack header %q: %w", name, err)
		}
		if _, err := writer.Write(data); err != nil {
			writer.Close()
			return fmt.Errorf("write evidence pack entry %q: %w", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close evidence pack archive: %w", err)
	}
	return nil
}

// VerifyEvidencePack verifies the current contract and every artifact its
// BundledArtifacts bind. It intentionally does not interpret an optional
// signature because a risk scan has no independently trusted signer here.
func VerifyEvidencePack(packDir string) EvidencePackVerification {
	result := EvidencePackVerification{}
	packData, err := readRiskScanArtifact(packDir, riskScanEvidencePackFile)
	if err != nil {
		return verificationError(result, err)
	}
	var pack contracts.EvidencePack
	if err := decodeSingleJSON(packData, &pack); err != nil {
		return verificationError(result, fmt.Errorf("decode evidence pack: %w", err))
	}
	result.PackID = pack.PackID
	if strings.TrimSpace(pack.Attestation.PackHash) == "" {
		return verificationError(result, fmt.Errorf("evidence pack attestation.pack_hash is required"))
	}
	if issues := executor.ValidateEvidencePack(&pack); len(issues) > 0 {
		return verificationError(result, fmt.Errorf("validate evidence pack: %s", strings.Join(issues, "; ")))
	}
	if pack.Attestation.Signature != "" || pack.Attestation.SignerID != "" {
		return verificationError(result, fmt.Errorf("risk scan evidence pack has an unsupported signature"))
	}
	if pack.Identity.ActorID != riskScanActorID || pack.Identity.ActorType != "module" || pack.Effect.EffectType != riskScanEffectType || pack.Execution.Status != "success" || pack.Policy.PolicyVersion != riskenvelope.SchemaVersion {
		return verificationError(result, fmt.Errorf("evidence pack is not a local risk scan export"))
	}

	envelopeData, err := readRiskScanArtifact(packDir, riskScanEnvelopeFile)
	if err != nil {
		return verificationError(result, err)
	}
	var envelope riskenvelope.RiskEnvelope
	if err := decodeSingleJSON(envelopeData, &envelope); err != nil {
		return verificationError(result, fmt.Errorf("decode risk envelope: %w", err))
	}
	canonicalEnvelope, err := EnvelopeJSON(envelope)
	if err != nil {
		return verificationError(result, fmt.Errorf("validate risk envelope: %w", err))
	}
	if !bytes.Equal(envelopeData, canonicalEnvelope) {
		return verificationError(result, fmt.Errorf("risk envelope is not the canonical exported representation"))
	}
	result.EnvelopeID = envelope.EnvelopeID
	envelopeHash := riskenvelope.SHA256Ref(envelopeData)
	if pack.Identity.SessionID != envelope.EnvelopeID || pack.Policy.DecisionID != "risk-scan:"+envelope.EnvelopeID || pack.Effect.EffectID != "risk-scan:"+envelope.EnvelopeID || pack.Policy.EvaluationGraphHash != envelope.SourcePackHash || pack.Effect.EffectPayloadHash != envelopeHash || pack.Execution.ResultHash != envelopeHash {
		return verificationError(result, fmt.Errorf("evidence pack is not bound to its risk envelope"))
	}

	allowed, err := verifyRiskScanArtifacts(packDir, pack.BundledArtifacts, envelopeHash)
	if err != nil {
		return verificationError(result, err)
	}
	if err := validateRiskScanLayout(packDir, allowed); err != nil {
		return verificationError(result, err)
	}
	result.Verified = true
	return result
}

func verifyRiskScanArtifacts(root string, artifacts []contracts.ParsedArtifact, envelopeHash string) (map[string]struct{}, error) {
	allowed := map[string]struct{}{riskScanEvidencePackFile: {}}
	seen := make(map[string]struct{}, len(artifacts))
	foundEnvelope := false
	for _, artifact := range artifacts {
		if artifact.ArtifactID == "" || artifact.URIRef == "" || artifact.Hash == "" || artifact.Inlinedigest != "" {
			return nil, fmt.Errorf("invalid bundled artifact")
		}
		if _, exists := seen[artifact.ArtifactID]; exists {
			return nil, fmt.Errorf("duplicate bundled artifact %q", artifact.ArtifactID)
		}
		seen[artifact.ArtifactID] = struct{}{}

		rel, err := cleanRiskScanArtifactPath(artifact.URIRef)
		if err != nil {
			return nil, err
		}
		switch artifact.Type {
		case "risk-envelope":
			if artifact.ArtifactID != "risk-envelope" || rel != riskScanEnvelopeFile || artifact.Hash != envelopeHash || foundEnvelope {
				return nil, fmt.Errorf("invalid risk envelope artifact")
			}
			foundEnvelope = true
		case "risk-scan-preview":
			if !strings.HasPrefix(artifact.ArtifactID, "preview:") {
				return nil, fmt.Errorf("invalid scan preview artifact")
			}
			name := strings.TrimPrefix(artifact.ArtifactID, "preview:")
			cleanName, err := cleanPreviewName(name)
			if err != nil || rel != filepath.ToSlash(filepath.Join(riskScanPreviewDir, cleanName)) {
				return nil, fmt.Errorf("invalid scan preview artifact")
			}
		default:
			return nil, fmt.Errorf("unsupported bundled artifact type %q", artifact.Type)
		}
		if _, exists := allowed[rel]; exists {
			return nil, fmt.Errorf("duplicate bundled artifact path %q", rel)
		}
		data, err := readRiskScanArtifact(root, rel)
		if err != nil {
			return nil, err
		}
		if riskenvelope.SHA256Ref(data) != artifact.Hash {
			return nil, fmt.Errorf("bundled artifact hash mismatch: %s", rel)
		}
		allowed[rel] = struct{}{}
	}
	if !foundEnvelope {
		return nil, fmt.Errorf("risk envelope artifact is required")
	}
	return allowed, nil
}

func validateRiskScanLayout(root string, allowed map[string]struct{}) error {
	hasPreview := len(allowed) > 2
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are not allowed in evidence pack")
		}
		if entry.IsDir() {
			if rel == riskScanPreviewDir && hasPreview {
				return nil
			}
			return fmt.Errorf("unexpected evidence pack directory %q", rel)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unsupported evidence pack entry %q", rel)
		}
		if _, ok := allowed[rel]; !ok {
			return fmt.Errorf("unexpected evidence pack entry %q", rel)
		}
		return nil
	})
}

func readRiskScanArtifact(root, rel string) ([]byte, error) {
	rel, err := cleanRiskScanArtifactPath(rel)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root, filepath.FromSlash(rel))
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read evidence pack entry %q: %w", rel, err)
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxRiskScanArtifactBytes {
		return nil, fmt.Errorf("invalid evidence pack entry %q", rel)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open evidence pack entry %q: %w", rel, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRiskScanArtifactBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read evidence pack entry %q: %w", rel, err)
	}
	if len(data) > maxRiskScanArtifactBytes {
		return nil, fmt.Errorf("evidence pack entry %q exceeds size limit", rel)
	}
	return data, nil
}

func cleanRiskScanArtifactPath(value string) (string, error) {
	value = filepath.ToSlash(strings.TrimSpace(value))
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, ":") {
		return "", fmt.Errorf("invalid evidence pack path %q", value)
	}
	clean := filepath.ToSlash(filepath.Clean(value))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("invalid evidence pack path %q", value)
	}
	return clean, nil
}

func decodeSingleJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func verificationError(result EvidencePackVerification, err error) EvidencePackVerification {
	result.Errors = []string{err.Error()}
	return result
}
