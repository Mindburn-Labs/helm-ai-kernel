package evidencepack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fixedTime() time.Time {
	return time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
}

func testBuilder() *Builder {
	return NewBuilder("p1", "did:helm:actor", "intent-1", "sha256:abc").
		WithCreatedAt(fixedTime())
}

// ---------------------------------------------------------------------------
// NewBuilder
// ---------------------------------------------------------------------------

func TestNewBuilder_FieldsStored(t *testing.T) {
	b := NewBuilder("id", "actor", "intent", "policy")
	if b.packID != "id" || b.actorDID != "actor" || b.intentID != "intent" || b.policyHash != "policy" {
		t.Fatal("constructor did not store fields")
	}
}

func TestNewBuilder_EmptyEntries(t *testing.T) {
	b := NewBuilder("id", "a", "i", "p")
	if len(b.entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(b.entries))
	}
}

func TestNewBuilder_DefaultCreatedAtIsUTC(t *testing.T) {
	b := NewBuilder("id", "a", "i", "p")
	if b.createdAt.Location() != time.UTC {
		t.Fatal("expected UTC")
	}
}

// ---------------------------------------------------------------------------
// WithCreatedAt
// ---------------------------------------------------------------------------

func TestWithCreatedAt_Overrides(t *testing.T) {
	ts := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	b := NewBuilder("id", "a", "i", "p").WithCreatedAt(ts)
	if !b.createdAt.Equal(ts) {
		t.Fatalf("expected %v, got %v", ts, b.createdAt)
	}
}

func TestWithCreatedAt_Chainable(t *testing.T) {
	b := NewBuilder("id", "a", "i", "p")
	ret := b.WithCreatedAt(fixedTime())
	if ret != b {
		t.Fatal("WithCreatedAt should return same pointer")
	}
}

// ---------------------------------------------------------------------------
// AddReceipt
// ---------------------------------------------------------------------------

func TestAddReceipt_PathPrefix(t *testing.T) {
	b := testBuilder()
	_ = b.AddReceipt("r1", map[string]string{"v": "ALLOW"})
	if _, ok := b.entries["receipts/r1.json"]; !ok {
		t.Fatal("expected receipts/r1.json key")
	}
}

func TestAddReceipt_ContentIsJSON(t *testing.T) {
	b := testBuilder()
	_ = b.AddReceipt("r1", map[string]string{"v": "ALLOW"})
	var out map[string]string
	if err := json.Unmarshal(b.entries["receipts/r1.json"].content, &out); err != nil {
		t.Fatalf("content is not valid JSON: %v", err)
	}
}

func TestAddReceipt_UnmarshalableError(t *testing.T) {
	b := testBuilder()
	err := b.AddReceipt("bad", make(chan int))
	if err == nil {
		t.Fatal("expected marshal error")
	}
}

// ---------------------------------------------------------------------------
// AddPolicyDecision
// ---------------------------------------------------------------------------

func TestAddPolicyDecision_PathPrefix(t *testing.T) {
	b := testBuilder()
	_ = b.AddPolicyDecision("d1", map[string]string{"verdict": "DENY"})
	if _, ok := b.entries["policy/d1.json"]; !ok {
		t.Fatal("expected policy/d1.json")
	}
}

func TestAddPolicyDecision_Error(t *testing.T) {
	b := testBuilder()
	if err := b.AddPolicyDecision("bad", make(chan int)); err == nil {
		t.Fatal("expected error for unmarshalable value")
	}
}

// ---------------------------------------------------------------------------
// AddToolTranscript
// ---------------------------------------------------------------------------

func TestAddToolTranscript_PathPrefix(t *testing.T) {
	b := testBuilder()
	_ = b.AddToolTranscript("t1", map[string]string{"tool": "bash"})
	if _, ok := b.entries["transcripts/t1.json"]; !ok {
		t.Fatal("expected transcripts/t1.json")
	}
}

func TestAddToolTranscript_ContentType(t *testing.T) {
	b := testBuilder()
	_ = b.AddToolTranscript("t1", "data")
	if b.entries["transcripts/t1.json"].contentType != "application/json" {
		t.Fatal("expected application/json")
	}
}

func TestAddToolTranscript_Error(t *testing.T) {
	b := testBuilder()
	if err := b.AddToolTranscript("bad", make(chan int)); err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// AddNetworkLog
// ---------------------------------------------------------------------------

func TestAddNetworkLog_PathAndContentType(t *testing.T) {
	b := testBuilder()
	_ = b.AddNetworkLog("egress", []byte("data"))
	e := b.entries["network/egress.log"]
	if e.contentType != "text/plain" {
		t.Fatalf("expected text/plain, got %s", e.contentType)
	}
}

func TestAddNetworkLog_EmptyReturnsError(t *testing.T) {
	b := testBuilder()
	if err := b.AddNetworkLog("x", nil); err == nil {
		t.Fatal("expected error for nil log")
	}
}

// ---------------------------------------------------------------------------
// AddSecretAccessLog
// ---------------------------------------------------------------------------

func TestAddSecretAccessLog_PathPrefix(t *testing.T) {
	b := testBuilder()
	_ = b.AddSecretAccessLog("s1", []string{"read", "write"})
	if _, ok := b.entries["secrets/s1.json"]; !ok {
		t.Fatal("expected secrets/s1.json")
	}
}

func TestAddSecretAccessLog_Error(t *testing.T) {
	b := testBuilder()
	if err := b.AddSecretAccessLog("bad", make(chan int)); err == nil {
		t.Fatal("expected marshal error")
	}
}

// ---------------------------------------------------------------------------
// AddPortExposure
// ---------------------------------------------------------------------------

func TestAddPortExposure_PathPrefix(t *testing.T) {
	b := testBuilder()
	_ = b.AddPortExposure("p1", map[string]int{"port": 443})
	if _, ok := b.entries["ports/p1.json"]; !ok {
		t.Fatal("expected ports/p1.json")
	}
}

func TestAddPortExposure_Error(t *testing.T) {
	b := testBuilder()
	if err := b.AddPortExposure("bad", make(chan int)); err == nil {
		t.Fatal("expected marshal error")
	}
}

// ---------------------------------------------------------------------------
// AddGitDiff
// ---------------------------------------------------------------------------

func TestAddGitDiff_PathAndContentType(t *testing.T) {
	b := testBuilder()
	_ = b.AddGitDiff("ws", []byte("diff --git a/f b/f"))
	e := b.entries["diffs/ws.diff"]
	if e.contentType != "text/x-diff" {
		t.Fatalf("expected text/x-diff, got %s", e.contentType)
	}
}

func TestAddGitDiff_EmptyReturnsError(t *testing.T) {
	b := testBuilder()
	if err := b.AddGitDiff("x", []byte{}); err == nil {
		t.Fatal("expected error for empty diff")
	}
}

// ---------------------------------------------------------------------------
// AddReplayManifest
// ---------------------------------------------------------------------------

func TestAddReplayManifest_PathPrefix(t *testing.T) {
	b := testBuilder()
	_ = b.AddReplayManifest("r1", map[string]string{"mode": "dry"})
	if _, ok := b.entries["replay/r1.json"]; !ok {
		t.Fatal("expected replay/r1.json")
	}
}

func TestAddReplayManifest_Error(t *testing.T) {
	b := testBuilder()
	if err := b.AddReplayManifest("bad", make(chan int)); err == nil {
		t.Fatal("expected marshal error")
	}
}

// ---------------------------------------------------------------------------
// AddRawEntry
// ---------------------------------------------------------------------------

func TestAddRawEntry_StoresExactBytes(t *testing.T) {
	b := testBuilder()
	raw := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	b.AddRawEntry("custom/bin.dat", "application/octet-stream", raw)
	if !bytes.Equal(b.entries["custom/bin.dat"].content, raw) {
		t.Fatal("raw bytes mismatch")
	}
}

func TestAddRawEntry_ContentTypePreserved(t *testing.T) {
	b := testBuilder()
	b.AddRawEntry("x/y", "image/png", []byte{1})
	if b.entries["x/y"].contentType != "image/png" {
		t.Fatal("content type not preserved")
	}
}

func TestAddRawEntry_OverwritesSamePath(t *testing.T) {
	b := testBuilder()
	b.AddRawEntry("a/b", "text/plain", []byte("first"))
	b.AddRawEntry("a/b", "text/plain", []byte("second"))
	if string(b.entries["a/b"].content) != "second" {
		t.Fatal("expected overwrite")
	}
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

func TestBuild_ErrorOnEmpty(t *testing.T) {
	b := testBuilder()
	_, _, err := b.Build()
	if err == nil {
		t.Fatal("expected error for empty pack")
	}
}

func TestBuild_ManifestVersion(t *testing.T) {
	b := testBuilder()
	b.AddRawEntry("f.txt", "text/plain", []byte("hi"))
	m, _, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != ManifestVersion {
		t.Fatalf("expected %s, got %s", ManifestVersion, m.Version)
	}
}

func TestBuild_ManifestFieldsMatch(t *testing.T) {
	b := testBuilder()
	b.AddRawEntry("f.txt", "text/plain", []byte("x"))
	m, _, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if m.PackID != "p1" || m.ActorDID != "did:helm:actor" || m.IntentID != "intent-1" || m.PolicyHash != "sha256:abc" {
		t.Fatal("manifest fields do not match builder inputs")
	}
}

func TestBuild_ManifestHashNonEmpty(t *testing.T) {
	b := testBuilder()
	b.AddRawEntry("f.txt", "text/plain", []byte("x"))
	m, _, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(m.ManifestHash, "sha256:") {
		t.Fatalf("unexpected hash prefix: %s", m.ManifestHash)
	}
}

func TestBuild_ContentMapIncludesManifest(t *testing.T) {
	b := testBuilder()
	b.AddRawEntry("f.txt", "text/plain", []byte("data"))
	_, cm, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cm["manifest.json"]; !ok {
		t.Fatal("expected manifest.json in content map")
	}
}

func TestBuild_ContentMapIncludesEntries(t *testing.T) {
	b := testBuilder()
	b.AddRawEntry("a.txt", "text/plain", []byte("a"))
	b.AddRawEntry("b.txt", "text/plain", []byte("b"))
	_, cm, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(cm) != 3 { // a.txt + b.txt + manifest.json
		t.Fatalf("expected 3 entries in content map, got %d", len(cm))
	}
}

func TestBuild_EntrySizeCorrect(t *testing.T) {
	b := testBuilder()
	b.AddRawEntry("f.txt", "text/plain", []byte("hello"))
	m, _, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if m.Entries[0].Size != 5 {
		t.Fatalf("expected size 5, got %d", m.Entries[0].Size)
	}
}

func TestBuild_EntryContentHashMatchesSHA256(t *testing.T) {
	b := testBuilder()
	data := []byte("deterministic content")
	b.AddRawEntry("f.txt", "text/plain", data)
	m, _, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	want := "sha256:" + hex.EncodeToString(h[:])
	if m.Entries[0].ContentHash != want {
		t.Fatalf("hash mismatch: got %s, want %s", m.Entries[0].ContentHash, want)
	}
}

func TestBuild_CreatedAtUsesOverride(t *testing.T) {
	b := testBuilder()
	b.AddRawEntry("f.txt", "text/plain", []byte("x"))
	m, _, _ := b.Build()
	if !m.CreatedAt.Equal(fixedTime()) {
		t.Fatalf("expected %v, got %v", fixedTime(), m.CreatedAt)
	}
}

// ---------------------------------------------------------------------------
// ComputeManifestHash
// ---------------------------------------------------------------------------

func TestComputeManifestHash_Deterministic(t *testing.T) {
	m := &Manifest{
		Version:    "1.0.0",
		PackID:     "p",
		CreatedAt:  fixedTime(),
		ActorDID:   "a",
		IntentID:   "i",
		PolicyHash: "ph",
		Entries: []ManifestEntry{
			{Path: "x", ContentHash: "sha256:aa", Size: 1, ContentType: "text/plain"},
		},
	}
	h1, err := ComputeManifestHash(m)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ComputeManifestHash(m)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("hash not deterministic")
	}
}

func TestComputeManifestHash_SortOrder(t *testing.T) {
	base := Manifest{
		Version: "1.0.0", PackID: "p", CreatedAt: fixedTime(),
		ActorDID: "a", IntentID: "i", PolicyHash: "ph",
	}
	m1 := base
	m1.Entries = []ManifestEntry{
		{Path: "a", ContentHash: "h1", Size: 1, ContentType: "t"},
		{Path: "b", ContentHash: "h2", Size: 1, ContentType: "t"},
	}
	m2 := base
	m2.Entries = []ManifestEntry{
		{Path: "b", ContentHash: "h2", Size: 1, ContentType: "t"},
		{Path: "a", ContentHash: "h1", Size: 1, ContentType: "t"},
	}
	h1, _ := ComputeManifestHash(&m1)
	h2, _ := ComputeManifestHash(&m2)
	if h1 != h2 {
		t.Fatal("hash should be order-independent")
	}
}

func TestComputeManifestHash_DiffersOnPackID(t *testing.T) {
	m1 := &Manifest{Version: "1.0.0", PackID: "a", CreatedAt: fixedTime(),
		Entries: []ManifestEntry{{Path: "x", ContentHash: "h", Size: 1, ContentType: "t"}}}
	m2 := &Manifest{Version: "1.0.0", PackID: "b", CreatedAt: fixedTime(),
		Entries: []ManifestEntry{{Path: "x", ContentHash: "h", Size: 1, ContentType: "t"}}}
	h1, _ := ComputeManifestHash(m1)
	h2, _ := ComputeManifestHash(m2)
	if h1 == h2 {
		t.Fatal("different pack IDs should produce different hashes")
	}
}

func TestComputeManifestHash_StartsWithSha256(t *testing.T) {
	m := &Manifest{Version: "1.0.0", PackID: "p", CreatedAt: fixedTime(),
		Entries: []ManifestEntry{{Path: "x", ContentHash: "h", Size: 1, ContentType: "t"}}}
	h, _ := ComputeManifestHash(m)
	if !strings.HasPrefix(h, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %s", h)
	}
}

func TestComputeManifestHash_Length(t *testing.T) {
	m := &Manifest{Version: "1.0.0", PackID: "p", CreatedAt: fixedTime(),
		Entries: []ManifestEntry{{Path: "x", ContentHash: "h", Size: 1, ContentType: "t"}}}
	h, _ := ComputeManifestHash(m)
	// "sha256:" (7) + 64 hex chars = 71
	if len(h) != 71 {
		t.Fatalf("expected length 71, got %d", len(h))
	}
}

// ---------------------------------------------------------------------------
// HashContent
// ---------------------------------------------------------------------------

func TestHashContent_KnownValue(t *testing.T) {
	h := sha256.Sum256([]byte("hello"))
	want := "sha256:" + hex.EncodeToString(h[:])
	got := HashContent([]byte("hello"))
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestHashContent_EmptyInput(t *testing.T) {
	got := HashContent([]byte{})
	if !strings.HasPrefix(got, "sha256:") {
		t.Fatal("expected sha256 prefix for empty input")
	}
}

// ---------------------------------------------------------------------------
// Archive / Unarchive round-trip
// ---------------------------------------------------------------------------

func TestArchiveUnarchive_RoundTrip(t *testing.T) {
	contents := map[string][]byte{
		"a.txt": []byte("aaa"),
		"b.txt": []byte("bbb"),
	}
	archive, err := Archive(contents)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unarchive(archive)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range contents {
		if !bytes.Equal(got[k], v) {
			t.Fatalf("mismatch for %s", k)
		}
	}
}

func TestArchive_ErrorOnEmpty(t *testing.T) {
	_, err := Archive(map[string][]byte{})
	if err == nil {
		t.Fatal("expected error for empty contents")
	}
}

func TestUnarchive_PreservesAllEntries(t *testing.T) {
	contents := map[string][]byte{"x": []byte("1"), "y": []byte("2"), "z": []byte("3")}
	ar, _ := Archive(contents)
	got, _ := Unarchive(ar)
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got))
	}
}

func TestArchive_Deterministic(t *testing.T) {
	contents := map[string][]byte{
		"b.txt": []byte("bbb"),
		"a.txt": []byte("aaa"),
	}
	ar1, _ := Archive(contents)
	ar2, _ := Archive(contents)
	if !bytes.Equal(ar1, ar2) {
		t.Fatal("archive should be deterministic")
	}
}

func TestArchive_DifferentInsertionOrderSameResult(t *testing.T) {
	c1 := map[string][]byte{"a": []byte("1"), "b": []byte("2")}
	c2 := map[string][]byte{"b": []byte("2"), "a": []byte("1")}
	a1, _ := Archive(c1)
	a2, _ := Archive(c2)
	if !bytes.Equal(a1, a2) {
		t.Fatal("insertion order should not affect archive bytes")
	}
}

func TestUnarchive_InvalidTarReturnsError(t *testing.T) {
	_, err := Unarchive([]byte("not a tar"))
	if err == nil {
		t.Fatal("expected error for invalid tar data")
	}
}

// ---------------------------------------------------------------------------
// Full Builder -> Archive -> Unarchive round-trip
// ---------------------------------------------------------------------------

func TestFullBuildArchiveUnarchiveRoundTrip(t *testing.T) {
	b := testBuilder()
	_ = b.AddReceipt("r1", map[string]string{"v": "ALLOW"})
	b.AddRawEntry("extra.bin", "application/octet-stream", []byte{1, 2, 3})

	_, cm, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}

	ar, err := Archive(cm)
	if err != nil {
		t.Fatal(err)
	}

	restored, err := Unarchive(ar)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(restored["extra.bin"], []byte{1, 2, 3}) {
		t.Fatal("restored content mismatch")
	}
	if _, ok := restored["manifest.json"]; !ok {
		t.Fatal("missing manifest.json after round-trip")
	}
}

// ---------------------------------------------------------------------------
// StreamBuilder
// ---------------------------------------------------------------------------

func TestStreamBuilder_NewFields(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "sp", "actor", "intent", "pol")
	if sb.packID != "sp" || sb.actorDID != "actor" {
		t.Fatal("fields not stored")
	}
}

func TestStreamBuilder_WithCreatedAt(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "sp", "a", "i", "p")
	ret := sb.WithCreatedAt(fixedTime())
	if ret != sb {
		t.Fatal("should return same pointer")
	}
	if !sb.createdAt.Equal(fixedTime()) {
		t.Fatal("time not set")
	}
}

func TestStreamBuilder_AddEntryTracksCount(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "sp", "a", "i", "p")
	sb.AddEntry("a.txt", []byte("a"), "text/plain")
	sb.AddEntry("b.txt", []byte("b"), "text/plain")
	if sb.EntryCount() != 2 {
		t.Fatalf("expected 2, got %d", sb.EntryCount())
	}
}

func TestStreamBuilder_FinalizeManifestHash(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "sp", "a", "i", "p").WithCreatedAt(fixedTime())
	sb.AddEntry("f.txt", []byte("data"), "text/plain")
	m, err := sb.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(m.ManifestHash, "sha256:") {
		t.Fatal("expected sha256 prefix")
	}
}

func TestStreamBuilder_AddEntryAfterFinalizeError(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "sp", "a", "i", "p")
	sb.AddEntry("f.txt", []byte("x"), "text/plain")
	sb.Finalize()
	if err := sb.AddEntry("g.txt", []byte("y"), "text/plain"); err == nil {
		t.Fatal("expected error after finalize")
	}
}

func TestStreamBuilder_AddToolTranscript(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "sp", "a", "i", "p").WithCreatedAt(fixedTime())
	_ = sb.AddToolTranscript("t1", map[string]string{"tool": "bash"})
	m, _ := sb.Finalize()
	if m.Entries[0].Path != "transcripts/t1.json" {
		t.Fatalf("unexpected path: %s", m.Entries[0].Path)
	}
}

// ---------------------------------------------------------------------------
// StreamReader
// ---------------------------------------------------------------------------

func TestStreamReader_ReadsAllEntries(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "sp", "a", "i", "p").WithCreatedAt(fixedTime())
	sb.AddEntry("a.txt", []byte("aaa"), "text/plain")
	sb.Finalize()

	sr := NewStreamReader(bytes.NewReader(buf.Bytes()))
	entries, err := sr.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	// 1 data entry + 1 manifest = 2
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestStreamReader_ManifestParsed(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "sp", "a", "i", "p").WithCreatedAt(fixedTime())
	sb.AddEntry("a.txt", []byte("aaa"), "text/plain")
	sb.Finalize()

	sr := NewStreamReader(bytes.NewReader(buf.Bytes()))
	sr.ReadAll()
	m := sr.Manifest()
	if m == nil {
		t.Fatal("manifest should not be nil after ReadAll")
	}
	if m.PackID != "sp" {
		t.Fatalf("expected sp, got %s", m.PackID)
	}
}

func TestStreamReader_EntryDataPreserved(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "sp", "a", "i", "p").WithCreatedAt(fixedTime())
	sb.AddEntry("a.txt", []byte("preserved"), "text/plain")
	sb.Finalize()

	sr := NewStreamReader(bytes.NewReader(buf.Bytes()))
	entry, _ := sr.Next()
	if string(entry.Data) != "preserved" {
		t.Fatalf("expected 'preserved', got %q", string(entry.Data))
	}
}

func TestStreamReader_EntryPath(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "sp", "a", "i", "p").WithCreatedAt(fixedTime())
	sb.AddEntry("my/path.txt", []byte("x"), "text/plain")
	sb.Finalize()

	sr := NewStreamReader(bytes.NewReader(buf.Bytes()))
	entry, _ := sr.Next()
	if entry.Path != "my/path.txt" {
		t.Fatalf("expected my/path.txt, got %s", entry.Path)
	}
}

// ---------------------------------------------------------------------------
// StreamBuilder + StreamReader round-trip
// ---------------------------------------------------------------------------

func TestStreamRoundTrip_ContentIntegrity(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "sp", "a", "i", "p").WithCreatedAt(fixedTime())
	sb.AddEntry("data/one.txt", []byte("one-content"), "text/plain")
	sb.AddEntry("data/two.txt", []byte("two-content"), "text/plain")
	sb.Finalize()

	sr := NewStreamReader(bytes.NewReader(buf.Bytes()))
	entries, _ := sr.ReadAll()

	found := map[string]string{}
	for _, e := range entries {
		if e.Path != "manifest.json" {
			found[e.Path] = string(e.Data)
		}
	}
	if found["data/one.txt"] != "one-content" || found["data/two.txt"] != "two-content" {
		t.Fatal("content integrity failed in stream round-trip")
	}
}
