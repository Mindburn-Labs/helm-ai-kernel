package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

// ExportManifest is written as manifest.json inside the evidence pack.
type ExportManifest struct {
	Version    string            `json:"version"`
	ExportedAt string            `json:"exported_at"`
	SessionID  string            `json:"session_id"`
	FileHashes map[string]string `json:"file_hashes"`
	PackHash   string            `json:"pack_hash,omitempty"`
}

// ExportPack creates a deterministic tar.gz evidence pack.
// Determinism: sorted paths, fixed mtime(0), stable uid/gid(0).
func ExportPack(sessionID string, files map[string][]byte, outPath string) error {
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Sort file names for determinism
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	// Compute file hashes
	fileHashes := make(map[string]string)
	for _, name := range names {
		h := sha256.Sum256(files[name])
		fileHashes[name] = hex.EncodeToString(h[:])
	}

	// Build manifest
	manifest := ExportManifest{
		Version:    "1.0",
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		SessionID:  sessionID,
		FileHashes: fileHashes,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	// Write manifest first
	if err := writeEntry(tw, "manifest.json", manifestBytes); err != nil {
		return err
	}

	// Write files
	for _, name := range names {
		if err := writeEntry(tw, name, files[name]); err != nil {
			return err
		}
	}

	return nil
}

func writeEntry(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Size:    int64(len(data)),
		Mode:    0644,
		ModTime: time.Unix(0, 0), // Deterministic: epoch
		Uid:     0,
		Gid:     0,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write header %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("write data %s: %w", name, err)
	}
	return nil
}

// VerifyPack reads and validates an evidence pack.
func VerifyPack(packPath string) (*ExportManifest, error) {
	f, err := os.Open(packPath)
	if err != nil {
		return nil, fmt.Errorf("open pack: %w", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	var manifest *ExportManifest
	fileHashes := make(map[string]string)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar read: %w", err)
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", hdr.Name, err)
		}

		if hdr.Name == "manifest.json" {
			var m ExportManifest
			if err := json.Unmarshal(data, &m); err != nil {
				return nil, fmt.Errorf("decode manifest: %w", err)
			}
			manifest = &m
		} else {
			h := sha256.Sum256(data)
			fileHashes[hdr.Name] = hex.EncodeToString(h[:])
		}
	}

	if manifest == nil {
		return nil, fmt.Errorf("manifest.json not found in pack")
	}

	// Verify file hashes
	for name, expectedHash := range manifest.FileHashes {
		actualHash, ok := fileHashes[name]
		if !ok {
			return nil, fmt.Errorf("file %s listed in manifest but missing from pack", name)
		}
		if actualHash != expectedHash {
			return nil, fmt.Errorf("hash mismatch for %s: expected %s, got %s", name, expectedHash, actualHash)
		}
	}

	return manifest, nil
}
