package evidencepack

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

// StreamBuilder constructs evidence packs incrementally by writing entries
// directly to an io.Writer, avoiding full in-memory buffering.
//
// Unlike Builder (which collects all entries in a map before archiving),
// StreamBuilder writes entries as they arrive. This enables multi-GB
// evidence packs that would exceed available memory.
//
// Usage:
//
//	sb := NewStreamBuilder(file, "pack-1", "did:helm:...", "intent-1", "sha256:...")
//	sb.AddEntry("receipts/r1.json", data, "application/json")
//	sb.AddEntry("transcripts/t1.json", data, "application/json")
//	manifest, err := sb.Finalize()
type StreamBuilder struct {
	writer     io.Writer
	tw         *tar.Writer
	packID     string
	actorDID   string
	intentID   string
	policyHash string
	createdAt  time.Time
	entries    []ManifestEntry // track entries for manifest
	finalized  bool
}

// NewStreamBuilder creates a streaming evidence pack builder.
// Entries are written directly to w as they are added.
func NewStreamBuilder(w io.Writer, packID, actorDID, intentID, policyHash string) *StreamBuilder {
	return &StreamBuilder{
		writer:     w,
		tw:         tar.NewWriter(w),
		packID:     packID,
		actorDID:   actorDID,
		intentID:   intentID,
		policyHash: policyHash,
		createdAt:  time.Now().UTC(),
	}
}

// WithCreatedAt overrides the creation timestamp for deterministic testing.
func (sb *StreamBuilder) WithCreatedAt(t time.Time) *StreamBuilder {
	sb.createdAt = t
	return sb
}

// AddEntry writes a single entry directly to the tar stream.
// The entry is hashed incrementally for the manifest.
func (sb *StreamBuilder) AddEntry(path string, data []byte, contentType string) error {
	if sb.finalized {
		return fmt.Errorf("stream builder already finalized")
	}

	// Compute content hash
	h := sha256.Sum256(data)
	contentHash := "sha256:" + hex.EncodeToString(h[:])

	// Write deterministic tar header
	var zeroTime time.Time
	hdr := &tar.Header{
		Name:    path,
		Size:    int64(len(data)),
		Mode:    0644,
		ModTime: zeroTime,
		Uid:     0,
		Gid:     0,
		Uname:   "",
		Gname:   "",
		Format:  tar.FormatPAX,
	}

	if err := sb.tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write tar header for %s: %w", path, err)
	}
	if _, err := sb.tw.Write(data); err != nil {
		return fmt.Errorf("write tar content for %s: %w", path, err)
	}

	// Track for manifest
	sb.entries = append(sb.entries, ManifestEntry{
		Path:        path,
		ContentHash: contentHash,
		Size:        int64(len(data)),
		ContentType: contentType,
	})

	return nil
}

// AddReceipt is a convenience method for adding JSON receipts.
func (sb *StreamBuilder) AddReceipt(name string, receipt interface{}) error {
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal receipt %s: %w", name, err)
	}
	return sb.AddEntry("receipts/"+name+".json", data, "application/json")
}

// AddToolTranscript is a convenience method for adding tool transcripts.
func (sb *StreamBuilder) AddToolTranscript(name string, transcript interface{}) error {
	data, err := json.MarshalIndent(transcript, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal transcript %s: %w", name, err)
	}
	return sb.AddEntry("transcripts/"+name+".json", data, "application/json")
}

// Finalize computes the manifest, writes it to the archive, and closes the tar.
// Returns the manifest with its computed hash.
func (sb *StreamBuilder) Finalize() (*Manifest, error) {
	if sb.finalized {
		return nil, fmt.Errorf("stream builder already finalized")
	}
	sb.finalized = true

	// Sort entries for deterministic manifest
	sort.Slice(sb.entries, func(i, j int) bool {
		return sb.entries[i].Path < sb.entries[j].Path
	})

	// Build manifest
	manifest := &Manifest{
		Version:    "1.0.0",
		PackID:     sb.packID,
		CreatedAt:  sb.createdAt,
		ActorDID:   sb.actorDID,
		IntentID:   sb.intentID,
		PolicyHash: sb.policyHash,
		Entries:    sb.entries,
	}

	// Compute manifest hash
	manifestHash, err := ComputeManifestHash(manifest)
	if err != nil {
		return nil, fmt.Errorf("compute manifest hash: %w", err)
	}
	manifest.ManifestHash = manifestHash

	// Write manifest as final entry in the tar
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}

	var zeroTime time.Time
	hdr := &tar.Header{
		Name:    "manifest.json",
		Size:    int64(len(manifestData)),
		Mode:    0644,
		ModTime: zeroTime,
		Uid:     0,
		Gid:     0,
		Format:  tar.FormatPAX,
	}
	if err := sb.tw.WriteHeader(hdr); err != nil {
		return nil, fmt.Errorf("write manifest header: %w", err)
	}
	if _, err := sb.tw.Write(manifestData); err != nil {
		return nil, fmt.Errorf("write manifest content: %w", err)
	}

	if err := sb.tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}

	return manifest, nil
}

// EntryCount returns the number of entries added so far.
func (sb *StreamBuilder) EntryCount() int {
	return len(sb.entries)
}
