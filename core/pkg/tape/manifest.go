package tape

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteManifest writes tape_manifest.json to the given directory per §5.3.
func WriteManifest(dir string, manifest *Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal tape manifest: %w", err)
	}
	path := filepath.Join(dir, "tape_manifest.json")
	return os.WriteFile(path, data, 0600)
}

// ReadManifest reads tape_manifest.json from the given directory.
func ReadManifest(dir string) (*Manifest, error) {
	path := filepath.Join(dir, "tape_manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tape manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse tape manifest: %w", err)
	}
	return &manifest, nil
}

// VerifyManifestIntegrity checks all manifest entries have valid hashes.
func VerifyManifestIntegrity(entries []Entry, manifest *Manifest) []string {
	var issues []string
	entryMap := make(map[uint64]*Entry, len(entries))
	for i := range entries {
		entryMap[entries[i].Seq] = &entries[i]
	}

	for _, item := range manifest.Entries {
		entry, ok := entryMap[item.Seq]
		if !ok {
			issues = append(issues, fmt.Sprintf("seq=%d referenced in manifest but not in entries", item.Seq))
			continue
		}
		h := sha256.Sum256(entry.Value)
		computed := hex.EncodeToString(h[:])
		if computed != item.SHA256 {
			issues = append(issues, fmt.Sprintf("seq=%d hash mismatch: expected %s, got %s", item.Seq, item.SHA256, computed))
		}
	}
	return issues
}
