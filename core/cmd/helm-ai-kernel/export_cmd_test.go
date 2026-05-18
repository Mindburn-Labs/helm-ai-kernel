package main

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestExportAuditArchivePreservesIndexedSidecars(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	evidenceDir := filepath.Join(root, "evidence")
	if err := os.MkdirAll(evidenceDir, 0750); err != nil {
		t.Fatal(err)
	}
	index := `{"entries":[{"path":"01_SCORE.json"},{"path":"01_SCORE.json.sha256"}]}`
	files := map[string]string{
		"00_INDEX.json":        index,
		"01_SCORE.json":        `{"pass":true}`,
		"01_SCORE.json.sha256": "hash  01_SCORE.json\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(evidenceDir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}

	outPath := filepath.Join(root, "evidence-pack.tar")
	var stdout, stderr bytes.Buffer
	if code := runExportCmd([]string{"--audit", "--evidence", evidenceDir, "--out", outPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("export exit code = %d stderr=%s", code, stderr.String())
	}

	archive, err := os.Open(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()

	found := map[string]bool{}
	tr := tar.NewReader(archive)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		found[hdr.Name] = true
	}
	if !found["01_SCORE.json.sha256"] {
		t.Fatalf("exported archive missing indexed sidecar; entries=%v", found)
	}
}
