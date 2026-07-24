package riskscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/riskenvelope"
)

const (
	// ScanEvidencePackProfile identifies the deliberately narrow, local scan
	// artifact. It is not a receipt-backed EvidencePack or ProofGraph.
	ScanEvidencePackProfile = "risk-scan/v1"

	scanEvidencePackScope           = "offline_integrity_only"
	scanEvidenceManifestPath        = "04_EXPORTS/scan-manifest.json"
	scanEvidenceEnvelopePath        = "04_EXPORTS/risk-envelope.json"
	scanEvidenceSummaryPath         = "04_EXPORTS/source-projection-summary.json"
	scanEvidenceSchemaPath          = "04_EXPORTS/schema-validation.json"
	scanEvidencePrivacyPath         = "04_EXPORTS/privacy-manifest.json"
	scanEvidenceSourceHashPath      = "04_EXPORTS/source-pack-hash.json"
	scanEvidenceSchemaReferencePath = "09_SCHEMAS/risk-envelope.v1.reference.json"
	scanEvidenceManifestSchemaPath  = "09_SCHEMAS/risk-scan-manifest.v1.json"

	riskEnvelopeSchemaURL    = "https://schemas.helm.mindburn.run/risk-envelope/v1.json"
	riskEnvelopeSchemaSHA256 = "sha256:191a483d4562a3b865aaa6ee2353a98c12220e07bd8c80163f9d88dee7c74505"
)

// EvidencePackOptions controls the local key location and deterministic time
// injection used while building a sealed scan pack.
type EvidencePackOptions struct {
	DataDir string
	Now     time.Time
}

// EvidencePackVerification is intentionally limited to offline artifact
// integrity. A successful result never verifies runtime receipt provenance,
// agent authorization, execution, or live posture.
type EvidencePackVerification struct {
	Profile             string   `json:"profile"`
	Verified            bool     `json:"verified"`
	VerificationScope   string   `json:"verification_scope"`
	EnvelopeID          string   `json:"envelope_id,omitempty"`
	EnvelopeContentHash string   `json:"envelope_content_hash,omitempty"`
	SourcePackHash      string   `json:"source_pack_hash,omitempty"`
	SourceKind          string   `json:"source_kind,omitempty"`
	Coverage            string   `json:"coverage,omitempty"`
	ReceiptProvenance   string   `json:"receipt_provenance,omitempty"`
	SealState           string   `json:"seal_state,omitempty"`
	Errors              []string `json:"errors,omitempty"`
}

type scanEvidencePackManifest struct {
	Profile             string `json:"profile"`
	SchemaVersion       string `json:"schema_version"`
	VerificationScope   string `json:"verification_scope"`
	SourceKind          string `json:"source_kind"`
	Coverage            string `json:"coverage"`
	ReceiptProvenance   string `json:"receipt_provenance"`
	SourceSummaryPath   string `json:"source_summary_path"`
	SourcePackHash      string `json:"source_pack_hash"`
	EnvelopePath        string `json:"envelope_path"`
	EnvelopeContentHash string `json:"envelope_content_hash"`
	GeneratedAt         string `json:"generated_at"`
}

type scanEvidencePackIndex struct {
	Profile string                   `json:"profile"`
	Entries []scanEvidenceIndexEntry `json:"entries"`
}

type scanEvidenceIndexEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type scanEvidenceSourceHash struct {
	SourcePackHash string `json:"source_pack_hash"`
	Meaning        string `json:"meaning"`
}

type scanEvidenceSchemaReference struct {
	SchemaVersion string `json:"schema_version"`
	SchemaURL     string `json:"schema_url"`
	SchemaSHA256  string `json:"schema_sha256"`
}

var scanEvidenceManifestSchema = []byte(`{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://schemas.helm.mindburn.run/risk-scan/v1/manifest.json",
  "title":"HELM local Risk Scan EvidencePack manifest v1",
  "type":"object",
  "additionalProperties":false,
  "required":["profile","schema_version","verification_scope","source_kind","coverage","receipt_provenance","source_summary_path","source_pack_hash","envelope_path","envelope_content_hash","generated_at"],
  "properties":{
    "profile":{"const":"risk-scan/v1"},
    "schema_version":{"const":"risk-envelope/v1"},
    "verification_scope":{"const":"offline_integrity_only"},
    "source_kind":{"enum":["static_config","receipt_projection"]},
    "coverage":{"const":"complete_declared_scope"},
    "receipt_provenance":{"enum":["not_applicable","unverified"]},
    "source_summary_path":{"const":"04_EXPORTS/source-projection-summary.json"},
    "source_pack_hash":{"type":"string","pattern":"^sha256:[a-f0-9]{64}$"},
    "envelope_path":{"const":"04_EXPORTS/risk-envelope.json"},
    "envelope_content_hash":{"type":"string","pattern":"^sha256:[a-f0-9]{64}$"},
    "generated_at":{"type":"string","format":"date-time"}
  }
}`)

// WriteEvidencePack writes a deterministic tar archive whose indexed files are
// sealed with a local file-dev key. It does not create any receipt, ProofGraph,
// Lamport clock, or claim of externally trusted provenance.
func WriteEvidencePack(path string, result ScanResult, previews map[string][]byte, opts EvidencePackOptions) error {
	if err := result.Envelope.Validate(); err != nil {
		return err
	}
	if err := validateScanResultForEvidence(result); err != nil {
		return err
	}
	canonicalSummary, err := canonicalize.JCS(result.sourceSummary)
	if err != nil {
		return fmt.Errorf("canonicalize source projection summary: %w", err)
	}
	if got := riskenvelope.SHA256Ref(canonicalSummary); got != result.Envelope.SourcePackHash {
		return fmt.Errorf("source projection summary hash mismatch: got %s want %s", got, result.Envelope.SourcePackHash)
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	dataDir, err := resolveScanEvidenceDataDir(opts.DataDir)
	if err != nil {
		return err
	}
	files, err := buildScanEvidenceFiles(result, canonicalSummary, previews, now)
	if err != nil {
		return err
	}

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	packDir, err := os.MkdirTemp(parent, ".risk-scan-pack-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(packDir)
	if err := writeScanEvidenceFiles(packDir, files); err != nil {
		return err
	}
	signer, err := evidencepkg.NewFileDevEvidenceSigner(dataDir)
	if err != nil {
		return fmt.Errorf("provision local scan evidence signer: %w", err)
	}
	trust := &evidencepkg.EvidencePackTrustConfig{ActiveProfile: evidencepkg.EvidenceTrustProfileDevLocal}
	if _, err := evidencepkg.SealEvidencePack(context.Background(), packDir, evidencepkg.SealEvidencePackOptions{
		PackID:      "risk-scan-" + strings.TrimPrefix(result.Envelope.EnvelopeContentHash, "sha256:")[:16],
		Profile:     evidencepkg.EvidenceTrustProfileDevLocal,
		Signer:      signer,
		TrustConfig: trust,
		SignedAt:    now,
		DataDir:     dataDir,
	}); err != nil {
		return fmt.Errorf("seal local scan evidence pack: %w", err)
	}
	archiveFiles, err := collectScanEvidenceFiles(packDir)
	if err != nil {
		return err
	}
	archive, err := evidencepack.Archive(archiveFiles)
	if err != nil {
		return fmt.Errorf("archive local scan evidence pack: %w", err)
	}
	return writeScanEvidenceArchive(path, archive)
}

func buildScanEvidenceFiles(result ScanResult, canonicalSummary []byte, previews map[string][]byte, now time.Time) (map[string][]byte, error) {
	envelopeJSON, err := EnvelopeJSON(result.Envelope)
	if err != nil {
		return nil, err
	}
	manifest := scanEvidencePackManifest{
		Profile:             ScanEvidencePackProfile,
		SchemaVersion:       riskenvelope.SchemaVersion,
		VerificationScope:   scanEvidencePackScope,
		SourceKind:          result.SourceKind,
		Coverage:            result.Coverage,
		ReceiptProvenance:   result.ReceiptProvenance,
		SourceSummaryPath:   scanEvidenceSummaryPath,
		SourcePackHash:      result.Envelope.SourcePackHash,
		EnvelopePath:        scanEvidenceEnvelopePath,
		EnvelopeContentHash: result.Envelope.EnvelopeContentHash,
		GeneratedAt:         now.Format(time.RFC3339),
	}
	files := map[string][]byte{
		scanEvidenceEnvelopePath: envelopeJSON,
		scanEvidenceSummaryPath:  append(append([]byte(nil), canonicalSummary...), '\n'),
		scanEvidenceSchemaPath:   jsonLine(schemaValidation(result.Envelope)),
		scanEvidencePrivacyPath:  jsonLine(PrivacyManifest{GeneratedBy: "helm-ai-kernel scan"}),
		scanEvidenceSourceHashPath: jsonLine(scanEvidenceSourceHash{
			SourcePackHash: result.Envelope.SourcePackHash,
			Meaning:        "sha256 of the canonical anonymized projection summary; not a raw source pack hash",
		}),
		scanEvidenceManifestPath: jsonLine(manifest),
		scanEvidenceSchemaReferencePath: jsonLine(scanEvidenceSchemaReference{
			SchemaVersion: riskenvelope.SchemaVersion,
			SchemaURL:     riskEnvelopeSchemaURL,
			SchemaSHA256:  riskEnvelopeSchemaSHA256,
		}),
		scanEvidenceManifestSchemaPath: append(append([]byte(nil), scanEvidenceManifestSchema...), '\n'),
	}
	for name, payload := range previews {
		clean, err := cleanScanPreviewPath(name)
		if err != nil {
			return nil, err
		}
		files["04_EXPORTS/previews/"+clean] = append([]byte(nil), payload...)
	}
	index, err := buildScanEvidenceIndex(files)
	if err != nil {
		return nil, err
	}
	files["00_INDEX.json"] = jsonLine(index)
	return files, nil
}

func validateScanResultForEvidence(result ScanResult) error {
	if result.sourceSummary == nil {
		return fmt.Errorf("scan evidence pack requires a scan result with an anonymized source projection summary")
	}
	switch result.SourceKind {
	case ScanSourceKindStaticConfig:
		if result.ReceiptProvenance != ReceiptProvenanceNotApplicable {
			return fmt.Errorf("static scan receipt provenance must be %q", ReceiptProvenanceNotApplicable)
		}
	case ScanSourceKindReceiptProjection:
		if result.ReceiptProvenance != ReceiptProvenanceUnverified {
			return fmt.Errorf("receipt projection provenance must be %q", ReceiptProvenanceUnverified)
		}
	default:
		return fmt.Errorf("unsupported scan source kind %q", result.SourceKind)
	}
	if result.Coverage != ScanCoverageCompleteDeclaredScope {
		return fmt.Errorf("scan evidence pack requires %q coverage", ScanCoverageCompleteDeclaredScope)
	}
	return nil
}

func buildScanEvidenceIndex(files map[string][]byte) (scanEvidencePackIndex, error) {
	names := make([]string, 0, len(files))
	for name := range files {
		if err := validateScanEvidenceContentPath(name); err != nil {
			return scanEvidencePackIndex{}, err
		}
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]scanEvidenceIndexEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, scanEvidenceIndexEntry{
			Path:   name,
			SHA256: strings.TrimPrefix(riskenvelope.SHA256Ref(files[name]), "sha256:"),
		})
	}
	return scanEvidencePackIndex{Profile: ScanEvidencePackProfile, Entries: entries}, nil
}

func cleanScanPreviewPath(name string) (string, error) {
	clean := filepath.ToSlash(filepath.Clean(strings.TrimSpace(name)))
	clean = strings.TrimPrefix(clean, "preview/")
	if clean == "" || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) {
		return "", fmt.Errorf("invalid scan preview path %q", name)
	}
	if ext := strings.ToLower(filepath.Ext(clean)); ext != ".md" && ext != ".html" {
		return "", fmt.Errorf("scan preview path must end in .md or .html: %q", name)
	}
	return clean, nil
}

func validateScanEvidenceContentPath(name string) error {
	clean := filepath.ToSlash(filepath.Clean(name))
	if clean != name || filepath.IsAbs(clean) || strings.HasPrefix(clean, "../") || clean == ".." {
		return fmt.Errorf("invalid scan evidence path %q", name)
	}
	return nil
}

func writeScanEvidenceFiles(root string, files map[string][]byte) error {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := validateScanEvidenceContentPath(name); err != nil {
			return err
		}
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, files[name], 0o600); err != nil {
			return err
		}
	}
	return nil
}

func collectScanEvidenceFiles(root string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("scan evidence pack contains symlink %s", d.Name())
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !validateScanEvidenceArchivePath(rel) {
			return fmt.Errorf("invalid scan evidence archive path %s", rel)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[rel] = data
		return nil
	})
	return files, err
}

func writeScanEvidenceArchive(path string, archive []byte) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".risk-scan-archive-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(archive); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func resolveScanEvidenceDataDir(dataDir string) (string, error) {
	if value := strings.TrimSpace(dataDir); value != "" {
		return value, nil
	}
	if value := strings.TrimSpace(os.Getenv("HELM_DATA_DIR")); value != "" {
		return value, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "", fmt.Errorf("scan evidence sealing requires --data-dir when no user home is available")
	}
	return filepath.Join(home, ".helm"), nil
}

// IsEvidencePack reports whether a directory declares the risk-scan/v1
// profile. It is used to keep the generic verifier from treating this local
// integrity artifact as a receipt-backed EvidencePack.
func IsEvidencePack(packDir string) bool {
	data, err := os.ReadFile(filepath.Join(packDir, scanEvidenceManifestPath))
	if err != nil {
		return false
	}
	var manifest scanEvidencePackManifest
	return json.Unmarshal(data, &manifest) == nil && manifest.Profile == ScanEvidencePackProfile
}

// VerifyEvidencePack verifies only the profile's sealed, offline artifact
// contract. It deliberately reports receipt provenance as unverified or not
// applicable instead of treating a local scan as proof of governed execution.
func VerifyEvidencePack(packDir string) EvidencePackVerification {
	result := EvidencePackVerification{
		Profile:           ScanEvidencePackProfile,
		VerificationScope: scanEvidencePackScope,
	}
	if err := validateScanEvidencePackLayout(packDir); err != nil {
		result.Errors = append(result.Errors, err.Error())
	}
	manifest, err := readScanEvidenceManifest(packDir)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	} else {
		result.SourceKind = manifest.SourceKind
		result.Coverage = manifest.Coverage
		result.ReceiptProvenance = manifest.ReceiptProvenance
		result.SourcePackHash = manifest.SourcePackHash
		result.EnvelopeContentHash = manifest.EnvelopeContentHash
		if err := validateScanEvidenceManifest(manifest); err != nil {
			result.Errors = append(result.Errors, err.Error())
		}
	}
	trust := &evidencepkg.EvidencePackTrustConfig{ActiveProfile: evidencepkg.EvidenceTrustProfileDevLocal}
	seal := evidencepkg.VerifyEvidencePackSeal(packDir, evidencepkg.VerifyEvidencePackSealOptions{
		Profile:     evidencepkg.EvidenceTrustProfileDevLocal,
		TrustConfig: trust,
	})
	result.SealState = seal.State
	if seal.State != "valid" || !seal.SignatureValid {
		if len(seal.Errors) == 0 {
			result.Errors = append(result.Errors, "local scan evidence seal is not valid")
		} else {
			result.Errors = append(result.Errors, seal.Errors...)
		}
	}
	envelope, err := readScanEvidenceEnvelope(packDir)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	} else {
		result.EnvelopeID = envelope.EnvelopeID
		if result.SourcePackHash != "" && result.SourcePackHash != envelope.SourcePackHash {
			result.Errors = append(result.Errors, "manifest source_pack_hash does not match risk envelope")
		}
		if result.EnvelopeContentHash != "" && result.EnvelopeContentHash != envelope.EnvelopeContentHash {
			result.Errors = append(result.Errors, "manifest envelope_content_hash does not match risk envelope")
		}
		result.SourcePackHash = envelope.SourcePackHash
		result.EnvelopeContentHash = envelope.EnvelopeContentHash
		if err := verifyScanEvidenceSummary(packDir, envelope.SourcePackHash); err != nil {
			result.Errors = append(result.Errors, err.Error())
		}
		if err := verifyScanEvidenceMetadata(packDir, envelope); err != nil {
			result.Errors = append(result.Errors, err.Error())
		}
	}
	result.Verified = len(result.Errors) == 0
	return result
}

func readScanEvidenceManifest(packDir string) (scanEvidencePackManifest, error) {
	var manifest scanEvidencePackManifest
	if err := readScanEvidenceJSON(filepath.Join(packDir, scanEvidenceManifestPath), &manifest); err != nil {
		return manifest, fmt.Errorf("read scan manifest: %w", err)
	}
	return manifest, nil
}

func validateScanEvidenceManifest(manifest scanEvidencePackManifest) error {
	if manifest.Profile != ScanEvidencePackProfile {
		return fmt.Errorf("unsupported scan evidence profile %q", manifest.Profile)
	}
	if manifest.SchemaVersion != riskenvelope.SchemaVersion || manifest.VerificationScope != scanEvidencePackScope ||
		manifest.SourceSummaryPath != scanEvidenceSummaryPath || manifest.EnvelopePath != scanEvidenceEnvelopePath {
		return fmt.Errorf("scan evidence manifest does not satisfy %s contract", ScanEvidencePackProfile)
	}
	if manifest.Coverage != ScanCoverageCompleteDeclaredScope {
		return fmt.Errorf("scan evidence coverage is not complete for its declared scope")
	}
	if manifest.SourceKind == ScanSourceKindStaticConfig && manifest.ReceiptProvenance != ReceiptProvenanceNotApplicable {
		return fmt.Errorf("static scan manifest has invalid receipt provenance")
	}
	if manifest.SourceKind == ScanSourceKindReceiptProjection && manifest.ReceiptProvenance != ReceiptProvenanceUnverified {
		return fmt.Errorf("receipt projection manifest has invalid receipt provenance")
	}
	if manifest.SourceKind != ScanSourceKindStaticConfig && manifest.SourceKind != ScanSourceKindReceiptProjection {
		return fmt.Errorf("scan evidence manifest has unsupported source kind %q", manifest.SourceKind)
	}
	return nil
}

func readScanEvidenceEnvelope(packDir string) (riskenvelope.RiskEnvelope, error) {
	var envelope riskenvelope.RiskEnvelope
	if err := readScanEvidenceJSON(filepath.Join(packDir, scanEvidenceEnvelopePath), &envelope); err != nil {
		return envelope, fmt.Errorf("read risk envelope: %w", err)
	}
	if err := envelope.Validate(); err != nil {
		return envelope, fmt.Errorf("validate risk envelope: %w", err)
	}
	return envelope, nil
}

func verifyScanEvidenceSummary(packDir, wantHash string) error {
	data, err := os.ReadFile(filepath.Join(packDir, scanEvidenceSummaryPath))
	if err != nil {
		return fmt.Errorf("read source projection summary: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var summary any
	if err := decoder.Decode(&summary); err != nil {
		return fmt.Errorf("parse source projection summary: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("source projection summary has trailing data")
	}
	canonical, err := canonicalize.JCS(summary)
	if err != nil {
		return fmt.Errorf("canonicalize source projection summary: %w", err)
	}
	if got := riskenvelope.SHA256Ref(canonical); got != wantHash {
		return fmt.Errorf("source projection summary hash mismatch: got %s want %s", got, wantHash)
	}
	var sourceHash scanEvidenceSourceHash
	if err := readScanEvidenceJSON(filepath.Join(packDir, scanEvidenceSourceHashPath), &sourceHash); err != nil {
		return fmt.Errorf("read source pack hash artifact: %w", err)
	}
	if sourceHash.SourcePackHash != wantHash || sourceHash.Meaning != "sha256 of the canonical anonymized projection summary; not a raw source pack hash" {
		return fmt.Errorf("source pack hash artifact does not match the risk-scan/v1 contract")
	}
	return nil
}

func verifyScanEvidenceMetadata(packDir string, envelope riskenvelope.RiskEnvelope) error {
	var schema SchemaValidation
	if err := readScanEvidenceJSON(filepath.Join(packDir, scanEvidenceSchemaPath), &schema); err != nil {
		return fmt.Errorf("read schema validation artifact: %w", err)
	}
	if !schema.Valid || schema.Schema != riskenvelope.SchemaVersion || schema.EnvelopeContentHash != envelope.EnvelopeContentHash {
		return fmt.Errorf("schema validation artifact does not match the risk envelope")
	}
	var privacy PrivacyManifest
	if err := readScanEvidenceJSON(filepath.Join(packDir, scanEvidencePrivacyPath), &privacy); err != nil {
		return fmt.Errorf("read privacy manifest: %w", err)
	}
	if privacy.RawPromptsCollected || privacy.SourceCodeCollected || privacy.SecretValuesCollected || privacy.CommandBodiesExported || privacy.SaltExported || privacy.RawSourcePackBundled || privacy.GeneratedBy != "helm-ai-kernel scan" {
		return fmt.Errorf("privacy manifest does not satisfy the local scan non-collection contract")
	}
	var schemaRef scanEvidenceSchemaReference
	if err := readScanEvidenceJSON(filepath.Join(packDir, scanEvidenceSchemaReferencePath), &schemaRef); err != nil {
		return fmt.Errorf("read risk envelope schema reference: %w", err)
	}
	if schemaRef.SchemaVersion != riskenvelope.SchemaVersion || schemaRef.SchemaURL != riskEnvelopeSchemaURL || schemaRef.SchemaSHA256 != riskEnvelopeSchemaSHA256 {
		return fmt.Errorf("risk envelope schema reference does not match the risk-scan/v1 contract")
	}
	manifestSchema, err := os.ReadFile(filepath.Join(packDir, scanEvidenceManifestSchemaPath))
	if err != nil {
		return fmt.Errorf("read scan manifest schema: %w", err)
	}
	if !bytes.Equal(manifestSchema, append(append([]byte(nil), scanEvidenceManifestSchema...), '\n')) {
		return fmt.Errorf("scan manifest schema does not match the risk-scan/v1 contract")
	}
	return nil
}

func readScanEvidenceJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func validateScanEvidencePackLayout(packDir string) error {
	required := map[string]bool{
		"00_INDEX.json":                  false,
		evidencepkg.EvidencePackSealPath: false,
		scanEvidenceManifestPath:         false,
		scanEvidenceEnvelopePath:         false,
		scanEvidenceSummaryPath:          false,
		scanEvidenceSchemaPath:           false,
		scanEvidencePrivacyPath:          false,
		scanEvidenceSourceHashPath:       false,
		scanEvidenceSchemaReferencePath:  false,
		scanEvidenceManifestSchemaPath:   false,
	}
	err := filepath.WalkDir(packDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(packDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("scan evidence pack contains symlink %s", rel)
		}
		if d.IsDir() {
			if rel != "04_EXPORTS" && rel != "04_EXPORTS/previews" && rel != "07_ATTESTATIONS" && rel != "09_SCHEMAS" {
				return fmt.Errorf("scan evidence pack contains unsupported directory %s", rel)
			}
			return nil
		}
		if !validateScanEvidenceArchivePath(rel) {
			return fmt.Errorf("scan evidence pack contains unsupported file %s", rel)
		}
		if _, ok := required[rel]; ok {
			required[rel] = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	for path, present := range required {
		if !present {
			return fmt.Errorf("scan evidence pack is missing required file %s", path)
		}
	}
	return nil
}

func validateScanEvidenceArchivePath(path string) bool {
	if path == "00_INDEX.json" || path == evidencepkg.EvidencePackSealPath {
		return true
	}
	switch path {
	case scanEvidenceManifestPath, scanEvidenceEnvelopePath, scanEvidenceSummaryPath, scanEvidenceSchemaPath,
		scanEvidencePrivacyPath, scanEvidenceSourceHashPath, scanEvidenceSchemaReferencePath, scanEvidenceManifestSchemaPath:
		return true
	}
	if strings.HasPrefix(path, "04_EXPORTS/previews/") {
		ext := strings.ToLower(filepath.Ext(path))
		return ext == ".md" || ext == ".html"
	}
	return false
}

func jsonLine(value any) []byte {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
}
