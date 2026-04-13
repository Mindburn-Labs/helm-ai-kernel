package evidencepack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"testing"
	"time"
)

func deepFixedTime() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

// ── 1-5: Builder with 100 entries ───────────────────────────────

func TestDeep_Builder100Entries(t *testing.T) {
	b := NewBuilder("pack-100", "did:helm:a", "intent-1", "sha256:abc")
	b.WithCreatedAt(deepFixedTime())
	for i := 0; i < 100; i++ {
		b.AddRawEntry(fmt.Sprintf("data/file_%03d.bin", i), "application/octet-stream", []byte(fmt.Sprintf("content-%d", i)))
	}
	m, contents, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 100 {
		t.Fatalf("want 100 entries got %d", len(m.Entries))
	}
	if len(contents) != 101 { // 100 data files + manifest.json
		t.Fatalf("want 101 content items got %d", len(contents))
	}
}

func TestDeep_BuilderEmptyFails(t *testing.T) {
	b := NewBuilder("empty", "did:helm:a", "intent-1", "sha256:abc")
	_, _, err := b.Build()
	if err == nil {
		t.Error("empty builder must fail")
	}
}

func TestDeep_BuilderManifestHashSet(t *testing.T) {
	b := NewBuilder("p1", "did:helm:a", "i1", "sha256:abc")
	b.WithCreatedAt(deepFixedTime())
	b.AddRawEntry("file.txt", "text/plain", []byte("hello"))
	m, _, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if m.ManifestHash == "" {
		t.Error("manifest hash should be set")
	}
}

func TestDeep_BuilderAllEntryTypes(t *testing.T) {
	b := NewBuilder("all-types", "did:helm:a", "i1", "sha256:abc")
	b.WithCreatedAt(deepFixedTime())
	b.AddReceipt("r1", map[string]string{"k": "v"})
	b.AddPolicyDecision("pd1", map[string]string{"k": "v"})
	b.AddToolTranscript("tt1", map[string]string{"k": "v"})
	b.AddNetworkLog("nl1", []byte("network data"))
	b.AddSecretAccessLog("sal1", map[string]string{"k": "v"})
	b.AddPortExposure("pe1", map[string]string{"k": "v"})
	b.AddGitDiff("gd1", []byte("diff content"))
	b.AddReplayManifest("rm1", map[string]string{"k": "v"})
	b.AddRawEntry("raw.bin", "application/octet-stream", []byte("raw"))
	m, _, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 9 {
		t.Fatalf("want 9 entries got %d", len(m.Entries))
	}
}

func TestDeep_BuilderContentHash(t *testing.T) {
	data := []byte("test content")
	h := sha256.Sum256(data)
	expected := "sha256:" + hex.EncodeToString(h[:])
	got := HashContent(data)
	if got != expected {
		t.Fatalf("hash mismatch: %s != %s", got, expected)
	}
}

// ── 6-10: Archive determinism ───────────────────────────────────

func TestDeep_ArchiveDeterminism(t *testing.T) {
	b1 := NewBuilder("det", "did:helm:a", "i1", "sha256:abc")
	b1.WithCreatedAt(deepFixedTime())
	for i := 0; i < 20; i++ {
		b1.AddRawEntry(fmt.Sprintf("f%d.txt", i), "text/plain", []byte(fmt.Sprintf("data-%d", i)))
	}
	m1, _, err := b1.Build()
	if err != nil {
		t.Fatal(err)
	}

	b2 := NewBuilder("det", "did:helm:a", "i1", "sha256:abc")
	b2.WithCreatedAt(deepFixedTime())
	for i := 0; i < 20; i++ {
		b2.AddRawEntry(fmt.Sprintf("f%d.txt", i), "text/plain", []byte(fmt.Sprintf("data-%d", i)))
	}
	m2, _, err := b2.Build()
	if err != nil {
		t.Fatal(err)
	}

	// Manifest hash is deterministic (entries are sorted before hashing)
	if m1.ManifestHash != m2.ManifestHash {
		t.Error("identical builds must produce identical manifest hashes")
	}
}

func TestDeep_ArchiveRoundTrip(t *testing.T) {
	contents := map[string][]byte{
		"a.txt": []byte("aaa"),
		"b.txt": []byte("bbb"),
	}
	arch, err := Archive(contents)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Unarchive(arch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored["a.txt"], []byte("aaa")) {
		t.Error("roundtrip a.txt failed")
	}
	if !bytes.Equal(restored["b.txt"], []byte("bbb")) {
		t.Error("roundtrip b.txt failed")
	}
}

func TestDeep_ArchiveEmpty(t *testing.T) {
	_, err := Archive(map[string][]byte{})
	if err == nil {
		t.Error("empty archive must fail")
	}
}

func TestDeep_ArchiveSortedOrder(t *testing.T) {
	contents := map[string][]byte{
		"z.txt": []byte("z"),
		"a.txt": []byte("a"),
		"m.txt": []byte("m"),
	}
	arch, _ := Archive(contents)
	restored, _ := Unarchive(arch)
	if len(restored) != 3 {
		t.Fatalf("want 3 entries got %d", len(restored))
	}
}

func TestDeep_ArchiveHashConsistency(t *testing.T) {
	contents := map[string][]byte{"test.txt": []byte("hello")}
	a1, _ := Archive(contents)
	a2, _ := Archive(contents)
	h1 := sha256.Sum256(a1)
	h2 := sha256.Sum256(a2)
	if h1 != h2 {
		t.Error("archive hashes must be identical for identical input")
	}
}

// ── 11-15: Manifest ─────────────────────────────────────────────

func TestDeep_ManifestHashDeterministic(t *testing.T) {
	m := &Manifest{
		Version:    ManifestVersion,
		PackID:     "p1",
		CreatedAt:  deepFixedTime(),
		ActorDID:   "did:helm:a",
		IntentID:   "i1",
		PolicyHash: "sha256:abc",
		Entries: []ManifestEntry{
			{Path: "b.txt", ContentHash: "sha256:b", Size: 1, ContentType: "text/plain"},
			{Path: "a.txt", ContentHash: "sha256:a", Size: 1, ContentType: "text/plain"},
		},
	}
	h1, _ := ComputeManifestHash(m)
	h2, _ := ComputeManifestHash(m)
	if h1 != h2 {
		t.Error("manifest hash must be deterministic")
	}
}

func TestDeep_ManifestHashSortIndependent(t *testing.T) {
	m1 := &Manifest{Version: "1.0.0", PackID: "p", CreatedAt: deepFixedTime(),
		Entries: []ManifestEntry{
			{Path: "z.txt", ContentHash: "sha256:z", Size: 1},
			{Path: "a.txt", ContentHash: "sha256:a", Size: 1},
		}}
	m2 := &Manifest{Version: "1.0.0", PackID: "p", CreatedAt: deepFixedTime(),
		Entries: []ManifestEntry{
			{Path: "a.txt", ContentHash: "sha256:a", Size: 1},
			{Path: "z.txt", ContentHash: "sha256:z", Size: 1},
		}}
	h1, _ := ComputeManifestHash(m1)
	h2, _ := ComputeManifestHash(m2)
	if h1 != h2 {
		t.Error("entry order must not affect manifest hash")
	}
}

func TestDeep_ManifestVersion(t *testing.T) {
	if ManifestVersion != "1.0.0" {
		t.Fatalf("unexpected manifest version: %s", ManifestVersion)
	}
}

func TestDeep_ManifestEntryContentType(t *testing.T) {
	b := NewBuilder("ct", "did:helm:a", "i1", "sha256:abc")
	b.WithCreatedAt(deepFixedTime())
	b.AddRawEntry("img.png", "image/png", []byte{0x89, 0x50, 0x4E, 0x47})
	m, _, _ := b.Build()
	for _, e := range m.Entries {
		if e.Path == "img.png" && e.ContentType != "image/png" {
			t.Error("content type mismatch")
		}
	}
}

func TestDeep_ManifestEntrySize(t *testing.T) {
	data := []byte("exactly 10")
	b := NewBuilder("sz", "did:helm:a", "i1", "sha256:abc")
	b.WithCreatedAt(deepFixedTime())
	b.AddRawEntry("f.txt", "text/plain", data)
	m, _, _ := b.Build()
	for _, e := range m.Entries {
		if e.Path == "f.txt" && e.Size != int64(len(data)) {
			t.Errorf("size %d != %d", e.Size, len(data))
		}
	}
}

// ── 16-20: Stream builder/reader with large payloads ────────────

func TestDeep_StreamBuilder1MB(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "stream-1mb", "did:helm:a", "i1", "sha256:abc")
	sb.WithCreatedAt(deepFixedTime())
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	err := sb.AddEntry("big.bin", largeData, "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	m, err := sb.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if m.Entries[0].Size != 1024*1024 {
		t.Fatalf("entry size %d != 1MB", m.Entries[0].Size)
	}
}

func TestDeep_StreamBuilderFinalizeTwice(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "p", "d", "i", "h")
	sb.AddEntry("f.txt", []byte("x"), "text/plain")
	sb.Finalize()
	_, err := sb.Finalize()
	if err == nil {
		t.Error("double finalize must error")
	}
}

func TestDeep_StreamBuilderAddAfterFinalize(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "p", "d", "i", "h")
	sb.AddEntry("f.txt", []byte("x"), "text/plain")
	sb.Finalize()
	err := sb.AddEntry("late.txt", []byte("y"), "text/plain")
	if err == nil {
		t.Error("add after finalize must error")
	}
}

func TestDeep_StreamReaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "rt", "did:helm:a", "i1", "sha256:abc")
	sb.WithCreatedAt(deepFixedTime())
	sb.AddEntry("a.txt", []byte("alpha"), "text/plain")
	sb.AddEntry("b.txt", []byte("beta"), "text/plain")
	sb.Finalize()

	sr := NewStreamReader(bytes.NewReader(buf.Bytes()))
	entries, err := sr.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	// 2 data entries + 1 manifest
	if len(entries) != 3 {
		t.Fatalf("want 3 entries got %d", len(entries))
	}
	if sr.Manifest() == nil {
		t.Error("manifest should be parsed")
	}
}

func TestDeep_StreamReaderEOF(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "eof", "d", "i", "h")
	sb.AddEntry("x.txt", []byte("x"), "text/plain")
	sb.Finalize()

	sr := NewStreamReader(bytes.NewReader(buf.Bytes()))
	count := 0
	for {
		_, err := sr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 2 { // x.txt + manifest.json
		t.Fatalf("want 2 entries got %d", count)
	}
}

// ── 21-25: Edge cases ───────────────────────────────────────────

func TestDeep_StreamEntryCount(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "ec", "d", "i", "h")
	for i := 0; i < 10; i++ {
		sb.AddEntry(fmt.Sprintf("f%d.txt", i), []byte("x"), "text/plain")
	}
	if sb.EntryCount() != 10 {
		t.Fatalf("want 10 got %d", sb.EntryCount())
	}
}

func TestDeep_NetworkLogEmpty(t *testing.T) {
	b := NewBuilder("nl", "d", "i", "h")
	err := b.AddNetworkLog("empty", nil)
	if err == nil {
		t.Error("empty network log must error")
	}
}

func TestDeep_GitDiffEmpty(t *testing.T) {
	b := NewBuilder("gd", "d", "i", "h")
	err := b.AddGitDiff("empty", nil)
	if err == nil {
		t.Error("empty git diff must error")
	}
}

func TestDeep_StreamBuilderManifestHash(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "mh", "d", "i", "sha256:abc")
	sb.WithCreatedAt(deepFixedTime())
	sb.AddEntry("data.bin", []byte("content"), "application/octet-stream")
	m, _ := sb.Finalize()
	if m.ManifestHash == "" {
		t.Error("stream manifest hash must be set")
	}
}

func TestDeep_StreamReceiptConvenience(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "rc", "d", "i", "h")
	err := sb.AddReceipt("r1", map[string]string{"status": "ok"})
	if err != nil {
		t.Fatal(err)
	}
	err = sb.AddToolTranscript("t1", map[string]string{"tool": "read"})
	if err != nil {
		t.Fatal(err)
	}
	if sb.EntryCount() != 2 {
		t.Fatalf("want 2 got %d", sb.EntryCount())
	}
}
