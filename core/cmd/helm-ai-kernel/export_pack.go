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
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ExportManifest is written as manifest.json inside the evidence pack.
type ExportManifest struct {
	Version        string                            `json:"version"`
	ExportedAt     string                            `json:"exported_at"`
	SessionID      string                            `json:"session_id"`
	FileHashes     map[string]string                 `json:"file_hashes"`
	PackHash       string                            `json:"pack_hash,omitempty"`
	EUAIActProfile *contracts.EUAIActEvidenceProfile `json:"eu_ai_act_profile,omitempty"`
	RedactionMeta  map[string]string                 `json:"redaction_metadata,omitempty"`
}

// ExportPackOptions controls optional evidence profile metadata.
type ExportPackOptions struct {
	EUAIActProfile  *contracts.EUAIActEvidenceProfile
	RedactionMeta   map[string]string
	TransparencySTH any
}

// ExportPack creates a deterministic tar.gz evidence pack.
// Determinism: sorted paths, fixed mtime(0), stable uid/gid(0).
func ExportPack(sessionID string, files map[string][]byte, outPath string) error {
	return ExportPackWithOptions(sessionID, files, outPath, ExportPackOptions{})
}

// ExportPackWithOptions creates a deterministic tar.gz evidence pack with
// optional compliance evidence metadata. Existing consumers can continue using
// ExportPack; profiles are validated only when explicitly supplied.
func ExportPackWithOptions(sessionID string, files map[string][]byte, outPath string, opts ExportPackOptions) error {
	if issues := contracts.ValidateEUAIActEvidenceProfile(opts.EUAIActProfile); len(issues) > 0 {
		return fmt.Errorf("invalid EU AI Act evidence profile: %s", strings.Join(issues, "; "))
	}
	exportFiles := files
	if opts.TransparencySTH != nil {
		if _, exists := files["transparency/sth.json"]; exists {
			return fmt.Errorf("transparency/sth.json already supplied by caller")
		}
		sthBytes, err := json.MarshalIndent(opts.TransparencySTH, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal transparency STH: %w", err)
		}
		exportFiles = make(map[string][]byte, len(files))
		for name, data := range files {
			exportFiles[name] = data
		}
		exportFiles["transparency/sth.json"] = sthBytes
	}
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
	names := make([]string, 0, len(exportFiles))
	for name := range exportFiles {
		names = append(names, name)
	}
	sort.Strings(names)

	// Compute file hashes
	fileHashes := make(map[string]string)
	for _, name := range names {
		h := sha256.Sum256(exportFiles[name])
		fileHashes[name] = hex.EncodeToString(h[:])
	}

	// Build manifest
	manifest := ExportManifest{
		Version:        "1.0",
		ExportedAt:     time.Now().UTC().Format(time.RFC3339),
		SessionID:      sessionID,
		FileHashes:     fileHashes,
		EUAIActProfile: opts.EUAIActProfile,
		RedactionMeta:  opts.RedactionMeta,
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
		if err := writeEntry(tw, name, exportFiles[name]); err != nil {
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
	seenEntries := make(map[string]struct{})

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar read: %w", err)
		}
		if hdr.Name == "" {
			return nil, fmt.Errorf("empty tar entry name")
		}
		if _, ok := seenEntries[hdr.Name]; ok {
			return nil, fmt.Errorf("duplicate tar entry %s", hdr.Name)
		}
		seenEntries[hdr.Name] = struct{}{}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return nil, fmt.Errorf("unsupported tar entry %s type %d", hdr.Name, hdr.Typeflag)
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
	if issues := contracts.ValidateEUAIActEvidenceProfile(manifest.EUAIActProfile); len(issues) > 0 {
		return nil, fmt.Errorf("invalid EU AI Act evidence profile: %s", strings.Join(issues, "; "))
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
	for name := range fileHashes {
		if _, ok := manifest.FileHashes[name]; !ok {
			return nil, fmt.Errorf("file %s present in pack but missing from manifest", name)
		}
	}

	return manifest, nil
}
