package main

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractEvidenceArchiveRejectsOversizedEntries(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "oversized.tar")
	file, err := os.Create(bundlePath)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	tarWriter := tar.NewWriter(file)
	if err := tarWriter.WriteHeader(&tar.Header{
		Name: "receipts/oversized.json",
		Mode: 0600,
		Size: maxEvidenceBundleBytes + 1,
	}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	// Intentionally do not close the tar writer: the extractor should reject
	// the declared size before attempting to consume the oversized body.
	if err := file.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}

	err = extractEvidenceArchive(bundlePath, t.TempDir())
	if err == nil {
		t.Fatal("expected oversized archive entry to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size-limit error, got %q", err.Error())
	}
}
