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

func TestExtractEvidenceArchiveRejectsTooManyEntries(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "entry-bomb.tar")
	file, err := os.Create(bundlePath)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	tarWriter := tar.NewWriter(file)
	for _, name := range []string{"one", "two", "three"} {
		if err := tarWriter.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0600,
			Size: 0,
		}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}

	err = extractEvidenceArchiveWithEntryLimit(bundlePath, t.TempDir(), 2)
	if err == nil || !strings.Contains(err.Error(), "exceeds 2 entries") {
		t.Fatalf("expected entry-limit error, got %v", err)
	}
}

func TestExtractCertifyArchiveRejectsOversizedEntries(t *testing.T) {
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
	if err := file.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}

	err = extractCertifyArchive(bundlePath, t.TempDir())
	if err == nil {
		t.Fatal("expected oversized archive entry to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size-limit error, got %q", err.Error())
	}
}

func TestExtractCertifyArchiveRejectsUnsupportedEntries(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "symlink.tar")
	file, err := os.Create(bundlePath)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	tarWriter := tar.NewWriter(file)
	if err := tarWriter.WriteHeader(&tar.Header{
		Name:     "receipts/link.json",
		Typeflag: tar.TypeSymlink,
		Linkname: "tool_receipt.json",
		Mode:     0600,
	}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}

	err = extractCertifyArchive(bundlePath, t.TempDir())
	if err == nil {
		t.Fatal("expected unsupported archive entry to be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported archive entry") {
		t.Fatalf("expected unsupported-entry error, got %q", err.Error())
	}
}

func TestSafeArchiveEntryPathRejectsEscapes(t *testing.T) {
	dst := t.TempDir()
	for _, name := range []string{
		"../escape.json",
		"receipts/../../escape.json",
		"/tmp/escape.json",
		`..\escape.json`,
		`C:\tmp\escape.json`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := safeArchiveEntryPath(dst, name); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestSafeArchiveEntryPathAllowsNestedLocalEntries(t *testing.T) {
	dst := t.TempDir()
	got, err := safeArchiveEntryPath(dst, "receipts/tool_receipt.json")
	if err != nil {
		t.Fatalf("expected nested local entry to be allowed: %v", err)
	}
	want := filepath.Join(dst, "receipts", "tool_receipt.json")
	if got != want {
		t.Fatalf("target path = %q, want %q", got, want)
	}
}
