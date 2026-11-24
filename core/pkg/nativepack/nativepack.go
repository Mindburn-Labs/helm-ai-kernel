// Package nativepack writes a native EvidencePack directory (00_INDEX.json,
// 01_SCORE.json, 02_PROOFGRAPH ... 12_REPORTS, 04_EXPORTS/launchpad_manifest.json
// and the receipt evidence graph) and its deterministic tar archive. `mcp proof`
// writes its pack with it, and `evidence inspect` reads the manifest and graph
// types. It moved out of the retired Launchpad tree (HELM-762); the pack layout
// and file names, including the launchpad_* exports that the sealer and the
// host-evidence attach command read, are unchanged.
package nativepack

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// Receipt is the receipt shape the evidence graph reads from 02_PROOFGRAPH/receipts.
type Receipt = contracts.Receipt

// Hash returns the sha256 digest of v's JSON encoding, prefixed "sha256:".
func Hash(v any) string {
	data, _ := json.Marshal(v)
	return HashBytes(data)
}

// HashBytes returns the sha256 digest of data, prefixed "sha256:".
func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type EvidencePackManifest struct {
	LaunchID   string            `json:"launch_id"`
	Version    string            `json:"version"`
	ExportedAt string            `json:"exported_at"`
	FileHashes map[string]string `json:"file_hashes"`
	Artifacts  map[string]string `json:"artifacts"`
}

type indexEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type evidenceIndex struct {
	Version string       `json:"version"`
	Entries []indexEntry `json:"entries"`
	Gates   []string     `json:"gates"`
}

type EvidenceGraph struct {
	Version  string              `json:"version"`
	LaunchID string              `json:"launch_id"`
	RootHash string              `json:"root_hash"`
	Nodes    []EvidenceGraphNode `json:"nodes"`
}

type EvidenceGraphNode struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Path         string `json:"path"`
	Verdict      string `json:"verdict,omitempty"`
	Hash         string `json:"hash"`
	PreviousHash string `json:"previous_hash,omitempty"`
	ChainHash    string `json:"chain_hash"`
}

func WriteEvidencePack(root, launchID string, artifacts map[string][]byte) (string, error) {
	dir := filepath.Join(root, "evidencepacks", launchID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for _, sub := range []string{"02_PROOFGRAPH", "03_TELEMETRY", "04_EXPORTS", "05_DIFFS", "06_LOGS", "07_ATTESTATIONS", "08_TAPES", "09_SCHEMAS", "11_HOST_EVIDENCE", "12_REPORTS"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return "", err
		}
	}
	if err := mergeExistingArtifacts(dir, artifacts); err != nil {
		return "", err
	}
	if _, ok := artifacts["proofgraph.json"]; !ok {
		artifacts["proofgraph.json"] = []byte(fmt.Sprintf(`{"version":"1.0.0","launch_id":%q,"nodes":[],"edges":[]}`, launchID))
	}
	hasReceipt := false
	for name := range artifacts {
		if strings.HasPrefix(name, "receipts/") {
			hasReceipt = true
			break
		}
	}
	if !hasReceipt {
		artifacts["receipts/launchpad-kernel-verdict.json"] = []byte(fmt.Sprintf(`{"receipt_id":"launchpad:%s","decision_id":"launchpad:%s","decision_hash":"%s","status":"ESCALATE","verdict":"ESCALATE","lamport_clock":1}`, launchID, launchID, HashBytes([]byte(launchID))))
	}
	addRequiredDirectoryPlaceholders(artifacts)
	redactEvidenceArtifacts(artifacts)
	graphData, err := buildEvidenceGraphArtifact(launchID, artifacts)
	if err != nil {
		return "", err
	}
	artifacts["launchpad_evidence_graph.json"] = graphData
	manifest := EvidencePackManifest{
		LaunchID:   launchID,
		Version:    "1.0.0",
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		FileHashes: map[string]string{},
		Artifacts:  map[string]string{},
	}
	index := evidenceIndex{Version: "1.0.0", Entries: []indexEntry{}, Gates: []string{"launchpad"}}
	keys := make([]string, 0, len(artifacts))
	for name := range artifacts {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	scoreData, err := json.MarshalIndent(map[string]any{
		"pass":      true,
		"run_id":    launchID,
		"scope":     "launchpad",
		"generated": manifest.ExportedAt,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	scoreData = append(scoreData, '\n')
	if err := os.WriteFile(filepath.Join(dir, "01_SCORE.json"), scoreData, 0o600); err != nil {
		return "", err
	}
	scoreHash := strings.TrimPrefix(HashBytes(scoreData), "sha256:")
	index.Entries = append(index.Entries, indexEntry{Path: "01_SCORE.json", SHA256: scoreHash})
	for _, name := range keys {
		data := artifacts[name]
		clean, err := cleanArtifactName(name)
		if err != nil {
			return "", err
		}
		clean = canonicalEvidencePath(clean)
		path := filepath.Join(dir, clean)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return "", err
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return "", err
		}
		hash := HashBytes(data)
		manifest.Artifacts[clean] = hash
		manifest.FileHashes[clean] = strings.TrimPrefix(hash, "sha256:")
		index.Entries = append(index.Entries, indexEntry{Path: clean, SHA256: strings.TrimPrefix(hash, "sha256:")})
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	manifestPath := filepath.Join(dir, "04_EXPORTS", "launchpad_manifest.json")
	if err := os.WriteFile(manifestPath, append(data, '\n'), 0o600); err != nil {
		return "", err
	}
	manifestHash := strings.TrimPrefix(HashBytes(append(data, '\n')), "sha256:")
	index.Entries = append(index.Entries, indexEntry{Path: "04_EXPORTS/launchpad_manifest.json", SHA256: manifestHash})
	sort.Slice(index.Entries, func(i, j int) bool { return index.Entries[i].Path < index.Entries[j].Path })
	indexData, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "00_INDEX.json"), append(indexData, '\n'), 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

func buildEvidenceGraphArtifact(launchID string, artifacts map[string][]byte) ([]byte, error) {
	graph := EvidenceGraph{
		Version:  "1.0.0",
		LaunchID: launchID,
		Nodes:    []EvidenceGraphNode{},
	}
	var receiptPaths []string
	for name := range artifacts {
		clean, err := cleanArtifactName(name)
		if err != nil {
			return nil, err
		}
		canonical := canonicalEvidencePath(clean)
		if strings.HasPrefix(canonical, "02_PROOFGRAPH/receipts/") {
			receiptPaths = append(receiptPaths, canonical)
		}
	}
	sort.Strings(receiptPaths)
	dataByPath := map[string][]byte{}
	for name, data := range artifacts {
		clean, err := cleanArtifactName(name)
		if err != nil {
			return nil, err
		}
		dataByPath[canonicalEvidencePath(clean)] = data
	}
	previous := ""
	for _, path := range receiptPaths {
		data := dataByPath[path]
		var receipt Receipt
		node := EvidenceGraphNode{
			ID:   path,
			Type: "receipt",
			Path: path,
			Hash: HashBytes(data),
		}
		if err := json.Unmarshal(data, &receipt); err == nil {
			node.ID = receipt.ReceiptID
			node.Type = receipt.Type
			node.Verdict = receipt.Verdict
		}
		node.PreviousHash = previous
		node.ChainHash = HashBytes([]byte(previous + "\n" + path + "\n" + node.Hash))
		graph.Nodes = append(graph.Nodes, node)
		previous = node.ChainHash
	}
	graph.RootHash = previous
	data, err := json.MarshalIndent(graph, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

var evidenceSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-(?:or|proj|ant|live|test)-[A-Za-z0-9_\-=]{8,}`),
	regexp.MustCompile(`ghp_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`hf_[A-Za-z0-9]{20,}`),
}

var evidenceSecretAssignmentPattern = regexp.MustCompile(evidenceSecretAssignmentPatternSource())

// providerCredentialEnvNames are the environment variables whose assigned
// values are redacted from pack artifacts: the provider credential and endpoint
// variables of the model-provider catalog Launchpad embedded, frozen when that
// catalog was retired with Launchpad.
var providerCredentialEnvNames = []string{
	"AI_ENDPOINT_API_KEY",
	"AI_GATEWAY_API_KEY",
	"ALEPH_ALPHA_API_KEY",
	"ANTHROPIC_API_KEY",
	"ARK_API_KEY",
	"AWS_ACCESS_KEY_ID",
	"AWS_BEARER_TOKEN_BEDROCK",
	"AWS_REGION",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AZURE_AI_FOUNDRY_ENDPOINT",
	"AZURE_AI_INFERENCE_ENDPOINT",
	"AZURE_INFERENCE_CREDENTIAL",
	"AZURE_OPENAI_API_KEY",
	"AZURE_OPENAI_API_VERSION",
	"AZURE_OPENAI_BASE_URL",
	"AZURE_OPENAI_DEPLOYMENT_NAME",
	"AZURE_OPENAI_ENDPOINT",
	"BAICHUAN_API_KEY",
	"BIGMODEL_API_KEY",
	"CEREBRAS_API_KEY",
	"CLOUDFLARE_AI_GATEWAY_BASE_URL",
	"CLOUDFLARE_API_TOKEN",
	"COHERE_API_KEY",
	"DASHSCOPE_API_KEY",
	"DEEPINFRA_API_KEY",
	"DEEPINFRA_TOKEN",
	"DEEPSEEK_API_KEY",
	"FIREWORKS_API_KEY",
	"GEMINI_API_KEY",
	"GITHUB_MODELS_TOKEN",
	"GOOGLE_API_KEY",
	"GOOGLE_APPLICATION_CREDENTIALS",
	"GOOGLE_CLOUD_LOCATION",
	"GOOGLE_CLOUD_PROJECT",
	"GOOGLE_VERTEX_ACCESS_TOKEN",
	"GOOGLE_VERTEX_BASE_URL",
	"GROQ_API_KEY",
	"HF_TOKEN",
	"HUGGINGFACE_API_KEY",
	"HUNYUAN_API_KEY",
	"IBM_CLOUD_API_KEY",
	"IBM_WATSONX_ACCESS_TOKEN",
	"IFLYTEK_SPARK_API_PASSWORD",
	"IONOS_API_TOKEN",
	"LINGYIWANWU_API_KEY",
	"MINIMAX_API_KEY",
	"MISTRAL_API_KEY",
	"MODELSCOPE_API_KEY",
	"MODELSCOPE_TOKEN",
	"MOONSHOT_API_KEY",
	"NEBIUS_API_KEY",
	"NVIDIA_API_KEY",
	"NVIDIA_NIM_API_KEY",
	"OPENAI_API_KEY",
	"OPENROUTER_API_KEY",
	"OVH_AI_ENDPOINTS_ACCESS_TOKEN",
	"PERPLEXITY_API_KEY",
	"QIANFAN_API_KEY",
	"REPLICATE_API_TOKEN",
	"SAMBANOVA_API_KEY",
	"SCALEWAY_API_KEY",
	"SCALEWAY_GENERATIVE_BASE_URL",
	"SCW_SECRET_KEY",
	"SILICONFLOW_API_KEY",
	"STEPFUN_API_KEY",
	"STEP_API_KEY",
	"TENCENT_HUNYUAN_API_KEY",
	"TOGETHER_API_KEY",
	"VERCEL_OIDC_TOKEN",
	"VOLCENGINE_API_KEY",
	"WATSONX_PROJECT_ID",
	"WATSONX_SPACE_ID",
	"WATSONX_URL",
	"XAI_API_KEY",
	"XFYUN_SPARK_API_PASSWORD",
	"YI_API_KEY",
	"ZHIPU_API_KEY",
}

func evidenceSecretAssignmentPatternSource() string {
	envNames := append([]string(nil), providerCredentialEnvNames...)
	// Existing evidence may still contain the retired catalog's CI aliases.
	// Preserve their redaction when the catalog itself is no longer shipped.
	for _, envName := range providerCredentialEnvNames {
		envNames = append(envNames, "HELM_LAUNCHPAD_CI_"+strings.TrimSuffix(envName, "_API_KEY")+"_API_KEY")
	}
	sort.Strings(envNames)
	for i, envName := range envNames {
		envNames[i] = regexp.QuoteMeta(envName)
	}
	return `(?i)(` + strings.Join(envNames, "|") + `)(["']?\s*[:=]\s*["']?)[A-Za-z0-9_\-\.=]{8,}`
}

func redactEvidenceArtifacts(artifacts map[string][]byte) {
	for name, data := range artifacts {
		artifacts[name] = redactEvidenceBytes(data)
	}
}

func redactEvidenceBytes(data []byte) []byte {
	redacted := string(data)
	for _, pattern := range evidenceSecretPatterns {
		redacted = pattern.ReplaceAllString(redacted, "[REDACTED_SECRET]")
	}
	redacted = evidenceSecretAssignmentPattern.ReplaceAllString(redacted, "${1}${2}[REDACTED_SECRET]")
	return []byte(redacted)
}

func addRequiredDirectoryPlaceholders(artifacts map[string][]byte) {
	for _, path := range []string{
		"03_TELEMETRY/.keep",
		"05_DIFFS/.keep",
		"06_LOGS/.keep",
		"07_ATTESTATIONS/.keep",
		"08_TAPES/.keep",
		"09_SCHEMAS/.keep",
		"11_HOST_EVIDENCE/.keep",
		"12_REPORTS/.keep",
	} {
		if _, exists := artifacts[path]; !exists {
			artifacts[path] = []byte("reserved for Launchpad EvidencePack conformance\n")
		}
	}
}

func mergeExistingArtifacts(dir string, artifacts map[string][]byte) error {
	if len(artifacts) == 0 {
		return nil
	}
	skip := map[string]struct{}{
		"00_INDEX.json": {},
		"01_SCORE.json": {},
		"04_EXPORTS/launchpad_evidence_graph.json": {},
		"04_EXPORTS/launchpad_manifest.json":       {},
		"07_ATTESTATIONS/evidence_pack.sig":        {},
	}
	return filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if _, shouldSkip := skip[rel]; shouldSkip {
			return nil
		}
		clean := rel
		if strings.HasPrefix(clean, "02_PROOFGRAPH/receipts/") {
			clean = strings.TrimPrefix(clean, "02_PROOFGRAPH/")
		}
		switch clean {
		case "02_PROOFGRAPH/proofgraph.json":
			clean = "proofgraph.json"
		}
		if _, exists := artifacts[clean]; exists {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304,G122: path comes from WalkDir over the pack directory this writer owns
		if err != nil {
			return err
		}
		artifacts[clean] = data
		return nil
	})
}

func WriteEvidencePackArchive(packDir string) (string, error) {
	info, err := os.Stat(packDir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("evidence pack archive source must be a directory")
	}
	archivePath := packDir + ".tar"
	file, err := os.OpenFile(archivePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // G304: the archive is written beside the pack directory the caller named
	if err != nil {
		return "", err
	}
	defer file.Close()
	tw := tar.NewWriter(file)
	defer tw.Close()

	var dirs []string
	var files []string
	if err := filepath.WalkDir(packDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != packDir {
				dirs = append(dirs, path)
			}
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		return "", err
	}
	sort.Strings(dirs)
	sort.Strings(files)
	for _, path := range dirs {
		rel, err := filepath.Rel(packDir, path)
		if err != nil {
			return "", err
		}
		header := &tar.Header{
			Name:     filepath.ToSlash(rel) + "/",
			Typeflag: tar.TypeDir,
			Mode:     0o700,
			ModTime:  time.Unix(0, 0).UTC(),
		}
		if err := tw.WriteHeader(header); err != nil {
			return "", err
		}
	}
	for _, path := range files {
		rel, err := filepath.Rel(packDir, path)
		if err != nil {
			return "", err
		}
		rel = filepath.ToSlash(rel)
		info, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		header := &tar.Header{
			Name:    rel,
			Mode:    0o600,
			Size:    info.Size(),
			ModTime: time.Unix(0, 0).UTC(),
		}
		if err := tw.WriteHeader(header); err != nil {
			return "", err
		}
		in, err := os.Open(path) //nolint:gosec // G304: path comes from WalkDir over the pack directory being archived
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(tw, in); err != nil {
			_ = in.Close()
			return "", err
		}
		if err := in.Close(); err != nil {
			return "", err
		}
	}
	return archivePath, nil
}

func canonicalEvidencePath(clean string) string {
	switch {
	case clean == "proofgraph.json":
		return "02_PROOFGRAPH/proofgraph.json"
	case strings.HasPrefix(clean, "receipts/"):
		return "02_PROOFGRAPH/" + clean
	case strings.HasPrefix(clean, "02_PROOFGRAPH/"),
		strings.HasPrefix(clean, "03_TELEMETRY/"),
		strings.HasPrefix(clean, "04_EXPORTS/"),
		strings.HasPrefix(clean, "05_DIFFS/"),
		strings.HasPrefix(clean, "06_LOGS/"),
		strings.HasPrefix(clean, "07_ATTESTATIONS/"),
		strings.HasPrefix(clean, "08_TAPES/"),
		strings.HasPrefix(clean, "09_SCHEMAS/"),
		strings.HasPrefix(clean, "11_HOST_EVIDENCE/"),
		strings.HasPrefix(clean, "12_REPORTS/"):
		return clean
	case strings.HasPrefix(clean, "host_evidence/"):
		return "11_HOST_EVIDENCE/" + strings.TrimPrefix(clean, "host_evidence/")
	default:
		return "04_EXPORTS/" + clean
	}
}

func cleanArtifactName(name string) (string, error) {
	clean := filepath.Clean(strings.TrimPrefix(name, "/"))
	if clean == "." || strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return "", fmt.Errorf("invalid evidence artifact path %q", name)
	}
	return clean, nil
}
