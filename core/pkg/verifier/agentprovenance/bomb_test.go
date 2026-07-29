package agentprovenance

// Regression: an agent provenance pack is a verification input from an
// untrusted source. Extraction previously used an unbounded io.Copy, so a small
// crafted archive could fill the disk of whoever was checking provenance.
//
// The pre-existing path-traversal check shows tar safety was considered; the
// size bound was the gap.

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeBombTar builds a tar whose single entry declares a huge size and streams
// highly compressible content.
func writeBombTar(t *testing.T, path string, declared int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	tw := tar.NewWriter(f)
	if err := tw.WriteHeader(&tar.Header{
		Name: "payload.bin",
		Mode: 0o600,
		Size: declared,
	}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	// Stream zeros without materialising them.
	if _, err := io.CopyN(tw, zeroReader{}, declared); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestExtractRefusesOversizedPack(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "bomb.tar")

	// Just over the cap, so the test stays fast while crossing the bound.
	writeBombTar(t, packPath, maxProvenancePackBytes+1024)

	extracted, cleanup, err := unpackTar(packPath)
	defer cleanup()

	if err == nil {
		t.Fatalf("an oversized pack extracted successfully into %s — the decompression "+
			"bound is not enforced", extracted)
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error should name the size limit, got: %v", err)
	}
}

// Negative control: a pack under the cap must still extract, otherwise the test
// above would pass simply because extraction is broken.
func TestExtractAcceptsNormalPack(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "ok.tar")
	writeBombTar(t, packPath, 4096)

	extracted, cleanup, err := unpackTar(packPath)
	defer cleanup()
	if err != nil {
		t.Fatalf("a normal pack failed to extract: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(extracted, "payload.bin")); statErr != nil {
		t.Fatalf("expected extracted payload: %v", statErr)
	}
}
