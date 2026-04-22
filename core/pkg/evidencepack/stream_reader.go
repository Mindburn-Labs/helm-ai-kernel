package evidencepack

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
)

// StreamEntry represents a single entry read incrementally from an evidence pack.
type StreamEntry struct {
	Path        string `json:"path"`
	ContentType string `json:"content_type,omitempty"`
	Size        int64  `json:"size"`
	Data        []byte `json:"data"`
}

// StreamReader reads evidence packs entry-by-entry without loading the full
// archive into memory. This enables processing multi-GB evidence packs.
//
// Usage:
//
//	sr := NewStreamReader(file)
//	for {
//	    entry, err := sr.Next()
//	    if err == io.EOF { break }
//	    if err != nil { return err }
//	    process(entry)
//	}
//	manifest := sr.Manifest()
type StreamReader struct {
	tr       *tar.Reader
	manifest *Manifest
}

// NewStreamReader creates a reader that iterates over evidence pack entries.
func NewStreamReader(r io.Reader) *StreamReader {
	return &StreamReader{
		tr: tar.NewReader(r),
	}
}

// Next returns the next entry in the evidence pack.
// Returns io.EOF when all entries have been read.
// The manifest entry (manifest.json) is parsed and stored internally;
// access it via Manifest() after reading all entries.
func (sr *StreamReader) Next() (*StreamEntry, error) {
	hdr, err := sr.tr.Next()
	if err != nil {
		return nil, err // io.EOF or read error
	}

	data, err := io.ReadAll(sr.tr)
	if err != nil {
		return nil, fmt.Errorf("read entry %s: %w", hdr.Name, err)
	}

	entry := &StreamEntry{
		Path: hdr.Name,
		Size: hdr.Size,
		Data: data,
	}

	// If this is the manifest, parse and store it
	if hdr.Name == "manifest.json" {
		var m Manifest
		if jsonErr := json.Unmarshal(data, &m); jsonErr == nil {
			sr.manifest = &m
		}
	}

	return entry, nil
}

// Manifest returns the parsed manifest if it has been read.
// Returns nil if the manifest entry hasn't been encountered yet.
func (sr *StreamReader) Manifest() *Manifest {
	return sr.manifest
}

// ReadAll reads all entries and returns them as a slice.
// For large packs, prefer using Next() iteratively instead.
func (sr *StreamReader) ReadAll() ([]*StreamEntry, error) {
	var entries []*StreamEntry
	for {
		entry, err := sr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
