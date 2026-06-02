package receipts

import (
	"archive/tar"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNewReceiptPopulatesHashesAndIDs(t *testing.T) {
	subject := map[string]any{"app_id": "demo", "digest": "sha256:abc"}

	receipt := NewReceipt("launchpad.install", "launch-123", "ALLOW", subject)

	if receipt.Type != "launchpad.install" || receipt.LaunchID != "launch-123" {
		t.Fatalf("unexpected receipt identity: %+v", receipt)
	}
	if receipt.DecisionID != "launchpad.install:launch-123" {
		t.Fatalf("unexpected decision id: %s", receipt.DecisionID)
	}
	if receipt.Verdict != "ALLOW" || receipt.Status != "ALLOW" || receipt.LamportClock != 1 {
		t.Fatalf("unexpected receipt status fields: %+v", receipt)
	}
	if !strings.HasPrefix(receipt.DecisionHash, "sha256:") || !strings.HasPrefix(receipt.Hash, "sha256:") {
		t.Fatalf("receipt hashes were not populated: %+v", receipt)
	}
	if receipt.ReceiptID != "launchpad.install:"+receipt.Hash {
		t.Fatalf("unexpected receipt id: %s", receipt.ReceiptID)
	}
	if receipt.CreatedAt.IsZero() || receipt.CreatedAt.Location() != time.UTC {
		t.Fatalf("receipt timestamp was not normalized to UTC: %v", receipt.CreatedAt)
	}
	if got := Hash(map[string]string{"stable": "value"}); !strings.HasPrefix(got, "sha256:") {
		t.Fatalf("Hash returned unexpected digest: %s", got)
	}
}

func TestWriteEvidencePackAddsDefaultReceiptAndCanonicalizesHostEvidence(t *testing.T) {
	packDir, err := WriteEvidencePack(t.TempDir(), "launch-defaults", map[string][]byte{
		"host_evidence/runtime.json": []byte(`{"host":"ci"}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{
		"02_PROOFGRAPH/proofgraph.json",
		"02_PROOFGRAPH/receipts/launchpad-kernel-verdict.json",
		"11_HOST_EVIDENCE/runtime.json",
	} {
		if _, err := os.Stat(filepath.Join(packDir, rel)); err != nil {
			t.Fatalf("expected default/canonical artifact %s: %v", rel, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(packDir, "04_EXPORTS", "launchpad_evidence_graph.json"))
	if err != nil {
		t.Fatal(err)
	}
	var graph EvidenceGraph
	if err := json.Unmarshal(data, &graph); err != nil {
		t.Fatal(err)
	}
	if len(graph.Nodes) != 1 || graph.Nodes[0].Verdict != "ESCALATE" {
		t.Fatalf("default receipt was not represented in evidence graph: %+v", graph)
	}
}

func TestWriteEvidencePackRejectsInvalidArtifactPath(t *testing.T) {
	if _, err := WriteEvidencePack(t.TempDir(), "launch-invalid", map[string][]byte{
		"../escape.json": []byte(`{}`),
	}); err == nil {
		t.Fatal("expected invalid artifact path to fail")
	}
}

func TestWriteEvidencePackReportsFilesystemFailures(t *testing.T) {
	receiptArtifact := map[string][]byte{
		"receipts/kernel.json": []byte(`{"receipt_id":"r1","type":"launchpad.kernel","decision_id":"d1","decision_hash":"sha256:test","status":"ALLOW","verdict":"ALLOW","lamport_clock":1}`),
	}

	rootFile := filepath.Join(t.TempDir(), "root-file")
	writeFile(t, rootFile, []byte("blocks mkdir"))
	if _, err := WriteEvidencePack(rootFile, "launch-root-file", copyArtifacts(receiptArtifact)); err == nil {
		t.Fatal("expected root file to block evidence pack directory creation")
	}

	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, packDir string)
		payload map[string][]byte
	}{
		{
			name: "required subdirectory path is file",
			setup: func(t *testing.T, packDir string) {
				writeFile(t, filepath.Join(packDir, "02_PROOFGRAPH"), []byte("not a directory"))
			},
			payload: receiptArtifact,
		},
		{
			name: "score path is directory",
			setup: func(t *testing.T, packDir string) {
				if err := os.Mkdir(filepath.Join(packDir, "01_SCORE.json"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			payload: receiptArtifact,
		},
		{
			name: "artifact parent path is file",
			setup: func(t *testing.T, packDir string) {
				writeFile(t, filepath.Join(packDir, "04_EXPORTS", "nested"), []byte("not a directory"))
			},
			payload: map[string][]byte{
				"nested/runtime.json": []byte(`{"ok":true}`),
			},
		},
		{
			name: "artifact target path is directory",
			setup: func(t *testing.T, packDir string) {
				if err := os.MkdirAll(filepath.Join(packDir, "04_EXPORTS", "runtime.json"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			payload: map[string][]byte{
				"runtime.json": []byte(`{"ok":true}`),
			},
		},
		{
			name: "manifest path is directory",
			setup: func(t *testing.T, packDir string) {
				if err := os.MkdirAll(filepath.Join(packDir, "04_EXPORTS", "launchpad_manifest.json"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			payload: receiptArtifact,
		},
		{
			name: "index path is directory",
			setup: func(t *testing.T, packDir string) {
				if err := os.Mkdir(filepath.Join(packDir, "00_INDEX.json"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			payload: receiptArtifact,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			launchID := strings.ReplaceAll(tc.name, " ", "-")
			packDir := filepath.Join(root, "evidencepacks", launchID)
			if err := os.MkdirAll(packDir, 0o700); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, packDir)

			if _, err := WriteEvidencePack(root, launchID, copyArtifacts(tc.payload)); err == nil {
				t.Fatal("expected filesystem collision to fail")
			}
		})
	}
}

func TestEvidencePathHelpers(t *testing.T) {
	tests := map[string]string{
		"proofgraph.json":                 "02_PROOFGRAPH/proofgraph.json",
		"receipts/kernel.json":            "02_PROOFGRAPH/receipts/kernel.json",
		"03_TELEMETRY/runtime.json":       "03_TELEMETRY/runtime.json",
		"host_evidence/externalhost.json": "11_HOST_EVIDENCE/externalhost.json",
		"summary.json":                    "04_EXPORTS/summary.json",
	}
	for input, want := range tests {
		if got := canonicalEvidencePath(input); got != want {
			t.Fatalf("canonicalEvidencePath(%q) = %q, want %q", input, got, want)
		}
	}

	for _, invalid := range []string{".", "../escape.json"} {
		if _, err := cleanArtifactName(invalid); err == nil {
			t.Fatalf("expected %q to be rejected", invalid)
		}
	}
	if clean, err := cleanArtifactName("/nested/../artifact.json"); err != nil || clean != "artifact.json" {
		t.Fatalf("unexpected cleaned artifact path %q: %v", clean, err)
	}
}

func TestMergeExistingArtifactsNormalizesLegacyPaths(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "00_INDEX.json"), []byte("skip-index"))
	writeFile(t, filepath.Join(dir, "01_SCORE.json"), []byte("skip-score"))
	writeFile(t, filepath.Join(dir, "04_EXPORTS", "launchpad_manifest.json"), []byte("skip-manifest"))
	writeFile(t, filepath.Join(dir, "04_EXPORTS", "launchpad_evidence_graph.json"), []byte("skip-graph"))
	writeFile(t, filepath.Join(dir, "02_PROOFGRAPH", "proofgraph.json"), []byte("proofgraph"))
	writeFile(t, filepath.Join(dir, "02_PROOFGRAPH", "receipts", "kernel.json"), []byte("receipt"))
	writeFile(t, filepath.Join(dir, "04_EXPORTS", "report.json"), []byte("report"))

	artifacts := map[string][]byte{
		"04_EXPORTS/report.json": []byte("new-report"),
	}
	if err := mergeExistingArtifacts(dir, artifacts); err != nil {
		t.Fatal(err)
	}
	if err := mergeExistingArtifacts(dir, map[string][]byte{}); err != nil {
		t.Fatal(err)
	}

	assertBytes(t, artifacts, "proofgraph.json", []byte("proofgraph"))
	assertBytes(t, artifacts, "receipts/kernel.json", []byte("receipt"))
	assertBytes(t, artifacts, "04_EXPORTS/report.json", []byte("new-report"))
	for _, skipped := range []string{"00_INDEX.json", "01_SCORE.json", "04_EXPORTS/launchpad_manifest.json", "04_EXPORTS/launchpad_evidence_graph.json"} {
		if _, ok := artifacts[skipped]; ok {
			t.Fatalf("expected %s to be skipped during merge", skipped)
		}
	}
}

func TestWriteEvidencePackArchiveWritesDeterministicTar(t *testing.T) {
	packDir, err := WriteEvidencePack(t.TempDir(), "launch-archive", map[string][]byte{
		"receipts/kernel-verdict.json": []byte(`{"receipt_id":"r1","type":"launchpad.kernel_verdict","decision_id":"d1","decision_hash":"sha256:test","status":"ALLOW","verdict":"ALLOW","lamport_clock":1}`),
		"03_TELEMETRY/runtime.json":    []byte(`{"ok":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	archivePath, err := WriteEvidencePackArchive(packDir)
	if err != nil {
		t.Fatal(err)
	}
	if archivePath != packDir+".tar" {
		t.Fatalf("unexpected archive path: %s", archivePath)
	}

	names, payloads := readTar(t, archivePath)
	if !sortsBefore(names, "02_PROOFGRAPH/", "00_INDEX.json") {
		t.Fatalf("archive should emit sorted directory entries before files: %v", names)
	}
	for _, rel := range []string{
		"00_INDEX.json",
		"01_SCORE.json",
		"02_PROOFGRAPH/receipts/kernel-verdict.json",
		"03_TELEMETRY/runtime.json",
		"04_EXPORTS/launchpad_manifest.json",
	} {
		if _, ok := payloads[rel]; !ok {
			t.Fatalf("archive missing %s; names=%v", rel, names)
		}
	}
	if string(payloads["03_TELEMETRY/runtime.json"]) != `{"ok":true}` {
		t.Fatalf("unexpected telemetry payload: %s", payloads["03_TELEMETRY/runtime.json"])
	}
}

func TestWriteEvidencePackArchiveRejectsInvalidSources(t *testing.T) {
	root := t.TempDir()
	if _, err := WriteEvidencePackArchive(filepath.Join(root, "missing")); err == nil {
		t.Fatal("expected missing source to fail")
	}

	filePath := filepath.Join(root, "source-file")
	writeFile(t, filePath, []byte("not a directory"))
	if _, err := WriteEvidencePackArchive(filePath); err == nil {
		t.Fatal("expected file source to fail")
	}

	packDir := filepath.Join(root, "pack")
	if err := os.Mkdir(packDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(packDir+".tar", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteEvidencePackArchive(packDir); err == nil {
		t.Fatal("expected archive path directory to fail")
	}

	brokenLinkPackDir := filepath.Join(root, "broken-link-pack")
	if err := os.Mkdir(brokenLinkPackDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(brokenLinkPackDir, "missing-target"), filepath.Join(brokenLinkPackDir, "broken-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteEvidencePackArchive(brokenLinkPackDir); err == nil {
		t.Fatal("expected broken symlink to fail archive file stat")
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertBytes(t *testing.T, artifacts map[string][]byte, key string, want []byte) {
	t.Helper()
	got, ok := artifacts[key]
	if !ok {
		t.Fatalf("missing merged artifact %s", key)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("artifact %s = %q, want %q", key, got, want)
	}
}

func copyArtifacts(artifacts map[string][]byte) map[string][]byte {
	copied := make(map[string][]byte, len(artifacts))
	for key, value := range artifacts {
		copied[key] = append([]byte(nil), value...)
	}
	return copied
}

func readTar(t *testing.T, path string) ([]string, map[string][]byte) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	reader := tar.NewReader(file)
	var names []string
	payloads := map[string][]byte{}
	for {
		header, err := reader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		names = append(names, header.Name)
		if !header.ModTime.Equal(time.Unix(0, 0).UTC()) {
			t.Fatalf("non-deterministic modtime for %s: %v", header.Name, header.ModTime)
		}
		if header.Typeflag == tar.TypeDir {
			if header.Mode != 0o700 {
				t.Fatalf("directory %s mode = %o", header.Name, header.Mode)
			}
			continue
		}
		if header.Mode != 0o600 {
			t.Fatalf("file %s mode = %o", header.Name, header.Mode)
		}
		buf, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		payloads[header.Name] = buf
	}
	return names, payloads
}

func sortsBefore(values []string, before, after string) bool {
	beforeIndex := -1
	afterIndex := -1
	for i, value := range values {
		switch value {
		case before:
			beforeIndex = i
		case after:
			afterIndex = i
		}
	}
	return beforeIndex >= 0 && afterIndex >= 0 && beforeIndex < afterIndex
}
