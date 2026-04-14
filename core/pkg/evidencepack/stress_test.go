package evidencepack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ────────────────────────────────────────────────────────────────────────
// Builder with 200 entries
// ────────────────────────────────────────────────────────────────────────

func TestStress_Builder200Entries(t *testing.T) {
	b := NewBuilder("pack-1", "did:helm:actor", "intent-1", "sha256:policy")
	for i := 0; i < 200; i++ {
		b.AddRawEntry(fmt.Sprintf("data/file-%d.bin", i), "application/octet-stream", []byte(fmt.Sprintf("content-%d", i)))
	}
	m, contents, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 200 {
		t.Fatalf("expected 200 entries, got %d", len(m.Entries))
	}
	if len(contents) != 201 { // 200 + manifest.json
		t.Fatalf("expected 201 content items, got %d", len(contents))
	}
}

func TestStress_Builder200Receipts(t *testing.T) {
	b := NewBuilder("pack-2", "did:helm:actor", "intent-2", "sha256:policy")
	for i := 0; i < 200; i++ {
		_ = b.AddReceipt(fmt.Sprintf("receipt-%d", i), map[string]string{"id": fmt.Sprintf("r-%d", i)})
	}
	m, _, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 200 {
		t.Fatalf("expected 200 entries, got %d", len(m.Entries))
	}
}

func TestStress_BuilderEmptyReturnsError(t *testing.T) {
	b := NewBuilder("pack-3", "did:helm:actor", "intent-3", "sha256:policy")
	_, _, err := b.Build()
	if err == nil {
		t.Fatal("expected error for empty builder")
	}
}

func TestStress_BuilderManifestHashDeterministic(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	build := func() string {
		b := NewBuilder("pack-d", "did:helm:actor", "intent-d", "sha256:policy")
		b.WithCreatedAt(ts)
		b.AddRawEntry("a.txt", "text/plain", []byte("hello"))
		m, _, _ := b.Build()
		return m.ManifestHash
	}
	h1 := build()
	h2 := build()
	if h1 != h2 {
		t.Fatalf("manifest hashes differ: %s vs %s", h1, h2)
	}
}

func TestStress_BuilderAddNetworkLog(t *testing.T) {
	b := NewBuilder("pack-n", "did:helm:actor", "intent-n", "sha256:policy")
	err := b.AddNetworkLog("access", []byte("log data"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = b.Build()
	if err != nil {
		t.Fatal(err)
	}
}

func TestStress_BuilderAddNetworkLogEmpty(t *testing.T) {
	b := NewBuilder("p", "d", "i", "h")
	err := b.AddNetworkLog("empty", []byte{})
	if err == nil {
		t.Fatal("expected error for empty network log")
	}
}

func TestStress_BuilderAddGitDiff(t *testing.T) {
	b := NewBuilder("p", "d", "i", "h")
	_ = b.AddGitDiff("diff-1", []byte("diff content"))
	m, _, _ := b.Build()
	if len(m.Entries) != 1 {
		t.Fatal("expected 1 entry")
	}
}

func TestStress_BuilderAddGitDiffEmpty(t *testing.T) {
	b := NewBuilder("p", "d", "i", "h")
	err := b.AddGitDiff("empty", []byte{})
	if err == nil {
		t.Fatal("expected error for empty git diff")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Archive 50 files
// ────────────────────────────────────────────────────────────────────────

func TestStress_Archive50Files(t *testing.T) {
	contents := make(map[string][]byte, 50)
	for i := 0; i < 50; i++ {
		contents[fmt.Sprintf("file-%03d.json", i)] = []byte(fmt.Sprintf(`{"id":%d}`, i))
	}
	data, err := Archive(contents)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := Unarchive(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 50 {
		t.Fatalf("expected 50 files, got %d", len(recovered))
	}
}

func TestStress_ArchiveDeterministic(t *testing.T) {
	contents := map[string][]byte{"b.txt": []byte("B"), "a.txt": []byte("A")}
	d1, _ := Archive(contents)
	d2, _ := Archive(contents)
	if !bytes.Equal(d1, d2) {
		t.Fatal("archives not deterministic")
	}
}

func TestStress_ArchiveEmptyReturnsError(t *testing.T) {
	_, err := Archive(map[string][]byte{})
	if err == nil {
		t.Fatal("expected error for empty archive")
	}
}

func TestStress_ArchiveRoundTrip(t *testing.T) {
	contents := map[string][]byte{"hello.txt": []byte("world")}
	data, _ := Archive(contents)
	recovered, _ := Unarchive(data)
	if string(recovered["hello.txt"]) != "world" {
		t.Fatal("round-trip failed")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Stream builder 100 entries
// ────────────────────────────────────────────────────────────────────────

func TestStress_StreamBuilder100Entries(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "pack-s", "did:helm:actor", "intent-s", "sha256:policy")
	for i := 0; i < 100; i++ {
		_ = sb.AddEntry(fmt.Sprintf("data/entry-%d.bin", i), []byte(fmt.Sprintf("data-%d", i)), "application/octet-stream")
	}
	m, err := sb.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 100 {
		t.Fatalf("expected 100, got %d", len(m.Entries))
	}
	if sb.EntryCount() != 100 {
		t.Fatalf("EntryCount mismatch: %d", sb.EntryCount())
	}
}

func TestStress_StreamBuilderFinalizedTwiceErrors(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "p", "d", "i", "h")
	_ = sb.AddEntry("a.txt", []byte("a"), "text/plain")
	_, _ = sb.Finalize()
	_, err := sb.Finalize()
	if err == nil {
		t.Fatal("expected error on second finalize")
	}
}

func TestStress_StreamBuilderAddAfterFinalizeErrors(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "p", "d", "i", "h")
	_ = sb.AddEntry("a.txt", []byte("a"), "text/plain")
	_, _ = sb.Finalize()
	err := sb.AddEntry("b.txt", []byte("b"), "text/plain")
	if err == nil {
		t.Fatal("expected error adding after finalize")
	}
}

func TestStress_StreamBuilderAddReceipt(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "p", "d", "i", "h")
	err := sb.AddReceipt("r1", map[string]string{"status": "ok"})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := sb.Finalize()
	if len(m.Entries) != 1 {
		t.Fatal("expected 1 entry")
	}
}

func TestStress_StreamBuilderAddToolTranscript(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "p", "d", "i", "h")
	err := sb.AddToolTranscript("t1", map[string]string{"tool": "file_read"})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := sb.Finalize()
	if len(m.Entries) != 1 {
		t.Fatal("expected 1 entry")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Manifest hash with all 8 entry types
// ────────────────────────────────────────────────────────────────────────

func TestStress_ManifestHashAllEntryTypes(t *testing.T) {
	b := NewBuilder("pack-types", "did:helm:a", "i-1", "sha256:p")
	_ = b.AddReceipt("r1", map[string]string{"status": "ok"})
	_ = b.AddPolicyDecision("pd1", map[string]string{"verdict": "ALLOW"})
	_ = b.AddToolTranscript("tt1", map[string]string{"tool": "t"})
	b.AddRawEntry("raw/r1.bin", "application/octet-stream", []byte("raw"))
	_ = b.AddNetworkLog("net1", []byte("net log"))
	_ = b.AddSecretAccessLog("sec1", map[string]string{"event": "access"})
	_ = b.AddPortExposure("port1", map[string]string{"port": "8080"})
	_ = b.AddGitDiff("diff1", []byte("diff content"))
	m, _, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 8 {
		t.Fatalf("expected 8 entries, got %d", len(m.Entries))
	}
	if m.ManifestHash == "" {
		t.Fatal("manifest hash not computed")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Round-trip with mixed content types
// ────────────────────────────────────────────────────────────────────────

func TestStress_RoundTripMixedContent(t *testing.T) {
	b := NewBuilder("pack-rt", "did:helm:a", "i-1", "sha256:p")
	_ = b.AddReceipt("r1", map[string]string{"id": "1"})
	b.AddRawEntry("binary.dat", "application/octet-stream", []byte{0x00, 0xff, 0xfe})
	_ = b.AddNetworkLog("net", []byte("tcp dump"))
	m, contents, _ := b.Build()
	archived, err := Archive(contents)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := Unarchive(archived)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	_ = json.Unmarshal(recovered["manifest.json"], &manifest)
	if manifest.PackID != m.PackID {
		t.Fatal("pack ID mismatch after round-trip")
	}
}

func TestStress_RoundTripVerifyHashes(t *testing.T) {
	b := NewBuilder("pack-h", "did:helm:a", "i-1", "sha256:p")
	data := []byte("important data")
	b.AddRawEntry("data.bin", "application/octet-stream", data)
	m, contents, _ := b.Build()
	for _, entry := range m.Entries {
		h := HashContent(contents[entry.Path])
		if h != entry.ContentHash {
			t.Fatalf("hash mismatch for %s: %s vs %s", entry.Path, h, entry.ContentHash)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────
// Concurrent build
// ────────────────────────────────────────────────────────────────────────

func TestStress_ConcurrentBuilderCreation(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			b := NewBuilder(fmt.Sprintf("pack-%d", n), "did:helm:a", fmt.Sprintf("i-%d", n), "sha256:p")
			for j := 0; j < 10; j++ {
				b.AddRawEntry(fmt.Sprintf("f-%d.bin", j), "application/octet-stream", []byte(fmt.Sprintf("d-%d-%d", n, j)))
			}
			_, _, err := b.Build()
			if err != nil {
				t.Errorf("build %d failed: %v", n, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestStress_ConcurrentStreamBuilderCreation(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			var buf bytes.Buffer
			sb := NewStreamBuilder(&buf, fmt.Sprintf("sp-%d", n), "d", fmt.Sprintf("i-%d", n), "h")
			for j := 0; j < 5; j++ {
				_ = sb.AddEntry(fmt.Sprintf("e-%d.bin", j), []byte("d"), "application/octet-stream")
			}
			_, err := sb.Finalize()
			if err != nil {
				t.Errorf("stream build %d failed: %v", n, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestStress_HashContentDeterministic(t *testing.T) {
	data := []byte("deterministic content")
	h1 := HashContent(data)
	h2 := HashContent(data)
	if h1 != h2 {
		t.Fatal("HashContent not deterministic")
	}
}

func TestStress_HashContentDifferentInputs(t *testing.T) {
	h1 := HashContent([]byte("a"))
	h2 := HashContent([]byte("b"))
	if h1 == h2 {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestStress_ManifestVersionConstant(t *testing.T) {
	if ManifestVersion != "1.0.0" {
		t.Fatalf("unexpected manifest version: %s", ManifestVersion)
	}
}

func TestStress_BuilderWithCreatedAtOverride(t *testing.T) {
	ts := time.Date(2020, 6, 15, 0, 0, 0, 0, time.UTC)
	b := NewBuilder("p", "d", "i", "h").WithCreatedAt(ts)
	b.AddRawEntry("x.bin", "application/octet-stream", []byte("x"))
	m, _, _ := b.Build()
	if !m.CreatedAt.Equal(ts) {
		t.Fatalf("expected overridden timestamp, got %v", m.CreatedAt)
	}
}

func TestStress_BuilderAddReplayManifest(t *testing.T) {
	b := NewBuilder("p", "d", "i", "h")
	err := b.AddReplayManifest("rm1", map[string]string{"mode": "dry"})
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := b.Build()
	if len(m.Entries) != 1 {
		t.Fatal("expected 1 entry")
	}
}

func TestStress_StreamBuilderManifestHashNonEmpty(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "p", "d", "i", "h")
	_ = sb.AddEntry("a.txt", []byte("a"), "text/plain")
	m, _ := sb.Finalize()
	if m.ManifestHash == "" {
		t.Fatal("manifest hash should be non-empty")
	}
}

func TestStress_StreamBuilderWithCreatedAt(t *testing.T) {
	ts := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "p", "d", "i", "h").WithCreatedAt(ts)
	_ = sb.AddEntry("a.txt", []byte("a"), "text/plain")
	m, _ := sb.Finalize()
	if !m.CreatedAt.Equal(ts) {
		t.Fatal("stream builder created_at override failed")
	}
}

func TestStress_ArchiveLargeFile(t *testing.T) {
	large := make([]byte, 1024*1024)
	for i := range large {
		large[i] = byte(i % 256)
	}
	contents := map[string][]byte{"large.bin": large}
	data, err := Archive(contents)
	if err != nil {
		t.Fatal(err)
	}
	recovered, _ := Unarchive(data)
	if len(recovered["large.bin"]) != len(large) {
		t.Fatal("large file round-trip size mismatch")
	}
}

func TestStress_ManifestHashStableWithDifferentInsertOrder(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	buildHash := func(first, second string) string {
		b := NewBuilder("p", "d", "i", "h").WithCreatedAt(ts)
		b.AddRawEntry(first, "application/octet-stream", []byte(first))
		b.AddRawEntry(second, "application/octet-stream", []byte(second))
		m, _, _ := b.Build()
		return m.ManifestHash
	}
	h1 := buildHash("a.bin", "z.bin")
	h2 := buildHash("z.bin", "a.bin")
	if h1 != h2 {
		t.Fatalf("manifest hash differs with different insertion order: %s vs %s", h1, h2)
	}
}

func TestStress_BuilderAddSecretAccessLog(t *testing.T) {
	b := NewBuilder("p", "d", "i", "h")
	err := b.AddSecretAccessLog("sec1", map[string]string{"event": "access"})
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := b.Build()
	if len(m.Entries) != 1 {
		t.Fatal("expected 1 entry")
	}
}

func TestStress_BuilderAddPortExposure(t *testing.T) {
	b := NewBuilder("p", "d", "i", "h")
	err := b.AddPortExposure("port1", map[string]string{"port": "443"})
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := b.Build()
	if len(m.Entries) != 1 {
		t.Fatal("expected 1 entry")
	}
}

func TestStress_BuilderAddPolicyDecision(t *testing.T) {
	b := NewBuilder("p", "d", "i", "h")
	err := b.AddPolicyDecision("pd1", map[string]string{"verdict": "DENY"})
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := b.Build()
	if len(m.Entries) != 1 {
		t.Fatal("expected 1 entry")
	}
}

func TestStress_BuilderAddToolTranscript(t *testing.T) {
	b := NewBuilder("p", "d", "i", "h")
	err := b.AddToolTranscript("t1", map[string]string{"tool": "file_read"})
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := b.Build()
	if len(m.Entries) != 1 {
		t.Fatal("expected 1 entry")
	}
}

func TestStress_HashContentPrefix(t *testing.T) {
	h := HashContent([]byte("test"))
	if len(h) < 7 || h[:7] != "sha256:" {
		t.Fatalf("hash should start with sha256:, got %s", h[:10])
	}
}

func TestStress_ComputeManifestHashDeterministic(t *testing.T) {
	m := &Manifest{Version: "1.0.0", PackID: "p1", ActorDID: "d", IntentID: "i", PolicyHash: "h",
		Entries: []ManifestEntry{{Path: "a.txt", ContentHash: "sha256:abc", Size: 3, ContentType: "text/plain"}}}
	h1, _ := ComputeManifestHash(m)
	h2, _ := ComputeManifestHash(m)
	if h1 != h2 {
		t.Fatal("manifest hash not deterministic")
	}
}

func TestStress_UnarchiveInvalidData(t *testing.T) {
	_, err := Unarchive([]byte("not a tar"))
	if err == nil {
		t.Fatal("expected error for invalid tar data")
	}
}

func TestStress_StreamBuilder100EntriesVerifyCount(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "p", "d", "i", "h")
	for i := 0; i < 100; i++ {
		_ = sb.AddEntry(fmt.Sprintf("e/%d.bin", i), []byte("d"), "application/octet-stream")
	}
	if sb.EntryCount() != 100 {
		t.Fatalf("expected 100, got %d", sb.EntryCount())
	}
	_, _ = sb.Finalize()
}

func TestStress_HashContentEmptyInput(t *testing.T) {
	h := HashContent([]byte{})
	if h == "" {
		t.Fatal("hash of empty input should not be empty string")
	}
}
