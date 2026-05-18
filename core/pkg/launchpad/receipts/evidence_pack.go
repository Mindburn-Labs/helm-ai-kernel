package receipts

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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

func WriteEvidencePack(root, launchID string, artifacts map[string][]byte) (string, error) {
	dir := filepath.Join(root, "evidencepacks", launchID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for _, sub := range []string{"02_PROOFGRAPH", "03_TELEMETRY", "04_EXPORTS", "05_DIFFS", "06_LOGS", "07_ATTESTATIONS", "08_TAPES", "09_SCHEMAS", "12_REPORTS"} {
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

func mergeExistingArtifacts(dir string, artifacts map[string][]byte) error {
	if len(artifacts) == 0 {
		return nil
	}
	skip := map[string]struct{}{
		"00_INDEX.json":                      {},
		"01_SCORE.json":                      {},
		"04_EXPORTS/launchpad_manifest.json": {},
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
		data, err := os.ReadFile(path)
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
	file, err := os.OpenFile(archivePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
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
		in, err := os.Open(path)
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
		strings.HasPrefix(clean, "12_REPORTS/"):
		return clean
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
