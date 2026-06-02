package replay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tape"
)

func TestReplayFromFileReadsJSONLAndReportsOpenError(t *testing.T) {
	r1 := Receipt{ID: "file-r1", ToolName: "calc", Timestamp: parseTime("2026-01-01T00:00:00Z"), LamportClock: 1}
	data1, _ := json.Marshal(r1)
	h1 := sha256.Sum256(data1)
	r2 := Receipt{ID: "file-r2", ToolName: "calc", PrevHash: hex.EncodeToString(h1[:]), Timestamp: parseTime("2026-01-01T00:00:01Z"), LamportClock: 2}

	line1, _ := json.Marshal(r1)
	line2, _ := json.Marshal(r2)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	if err := os.WriteFile(path, append(append(line1, '\n'), line2...), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ReplayFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalReceipts != 2 || !result.ValidChain {
		t.Fatalf("unexpected replay result: %+v", result)
	}

	if _, err := ReplayFromFile(filepath.Join(t.TempDir(), "missing.jsonl")); err == nil {
		t.Fatal("expected missing replay file to fail")
	}
}

func TestReplayFromReaderReportsDecodeError(t *testing.T) {
	if _, err := ReplayFromReader(strings.NewReader("{not-json")); err == nil {
		t.Fatal("expected malformed replay JSONL to fail")
	}
}

func TestVisualizerLineageAndSummaryBranches(t *testing.T) {
	events := []TimelineEvent{
		{
			EventID:    "root",
			Type:       EventTypeDelegation,
			Actor:      "alice",
			Action:     "delegate",
			Verdict:    "ALLOW",
			ReasonCode: "delegated",
			Depth:      1,
		},
		{
			EventID:    "child",
			ParentID:   "root",
			Type:       EventTypeEffect,
			Actor:      "bob",
			Action:     "execute",
			Verdict:    "ALLOW",
			ReasonCode: "effect",
			Depth:      2,
		},
		{
			EventID:    "leaf",
			ParentID:   "child",
			Type:       EventTypeError,
			Actor:      "bob",
			Action:     "fail",
			Verdict:    "ERROR",
			ReasonCode: "runtime_error",
			Depth:      3,
		},
	}

	lineage, err := TraceLineage("lineage-1", events, "leaf")
	if err != nil {
		t.Fatal(err)
	}
	if lineage.RootEvent != "root" || lineage.LeafEvent != "leaf" || lineage.TotalDepth != 3 {
		t.Fatalf("unexpected lineage: %+v", lineage)
	}

	summary := computeSummary(events)
	if summary.Delegations != 1 || summary.Effects != 1 || summary.Errors != 1 {
		t.Fatalf("unexpected event counts: %+v", summary)
	}
	if summary.UniqueActors != 2 || summary.MaxDepth != 3 {
		t.Fatalf("unexpected actor/depth summary: %+v", summary)
	}
	if summary.ReasonCodes["runtime_error"] != 1 {
		t.Fatalf("reason codes were not counted: %+v", summary.ReasonCodes)
	}
}

func TestClassifyEventAdditionalStatuses(t *testing.T) {
	for _, tc := range []struct {
		status string
		want   TimelineEventType
	}{
		{status: "ESCALATED", want: EventTypeEscalation},
		{status: "ERROR", want: EventTypeError},
		{status: "SUCCESS", want: EventTypeEffect},
	} {
		if got := classifyEvent(Receipt{Status: tc.status}); got != tc.want {
			t.Fatalf("classifyEvent(%q) = %s, want %s", tc.status, got, tc.want)
		}
	}
}

func TestTapeBridgeLoadsManifestEntriesAndConvertsEvents(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	entries := []tape.Entry{
		replayTapeEntry(1, tape.EntryTypeRNGSeed, "rng", "seed-key", []byte("seed-value"), now),
		replayTapeEntry(2, tape.EntryTypeNetwork, "network", "https://example.test", []byte("response-body"), now.Add(time.Second)),
	}
	writeReplayTapeFixture(t, dir, entries, nil)

	source := NewTapeEventSource(dir)
	events, err := source.GetRunEvents(context.Background(), "ignored-run-id")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].SequenceNumber != 1 || events[0].EventID != "rng" || events[0].PRNGSeed != "seed-key" {
		t.Fatalf("unexpected RNG event conversion: %+v", events[0])
	}
	if events[0].PayloadHash != entries[0].ValueHash || events[0].OutputHash != entries[0].ValueHash {
		t.Fatalf("hashes were not mapped from tape entry: %+v", events[0])
	}
	if got := events[0].Payload["tape_value"]; got != "seed-value" {
		t.Fatalf("unexpected tape payload value: %#v", got)
	}
	if got := events[0].Payload["data_class"]; got != "PUBLIC" {
		t.Fatalf("unexpected data class payload: %#v", got)
	}

	loaded, err := LoadTapeEntries(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != len(entries) {
		t.Fatalf("expected %d loaded entries, got %d", len(entries), len(loaded))
	}

	hash, err := ComputeTapeRunHash(entries)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("unexpected tape run hash: %s", hash)
	}
}

func TestTapeBridgeConvertsRunEventToTapeEntry(t *testing.T) {
	event := RunEvent{
		SequenceNumber: 7,
		EventID:        "component",
		EventType:      string(tape.EntryTypeRNGSeed),
		PayloadHash:    "hash-7",
		PRNGSeed:       "seed-7",
		Timestamp:      time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC),
		Payload: map[string]interface{}{
			"data_class":       "CONFIDENTIAL",
			"residency_region": "DE",
			"encryption":       "AES-256-GCM",
			"retention_basis":  "contract",
		},
	}

	entry := RunEventToTapeEntry(event)
	if entry.Seq != event.SequenceNumber || entry.Type != tape.EntryTypeRNGSeed || entry.ComponentID != event.EventID {
		t.Fatalf("unexpected tape entry identity: %+v", entry)
	}
	if entry.Key != "seed-7" || entry.ValueHash != "hash-7" {
		t.Fatalf("unexpected tape key/hash: %+v", entry)
	}
	if entry.DataClass != "CONFIDENTIAL" || entry.ResidencyRegion != "DE" ||
		entry.Encryption != "AES-256-GCM" || entry.RetentionBasis != "contract" {
		t.Fatalf("payload metadata was not copied: %+v", entry)
	}
}

func TestTapeEventSourceReportsManifestLoadAndIntegrityErrors(t *testing.T) {
	if _, err := NewTapeEventSource(t.TempDir()).GetRunEvents(context.Background(), "run"); err == nil {
		t.Fatal("expected missing manifest to fail")
	}

	t.Run("entry read error", func(t *testing.T) {
		dir := t.TempDir()
		writeReplayTapeManifest(t, dir, nil)
		if err := os.Mkdir(filepath.Join(dir, "entry_0001.json"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := NewTapeEventSource(dir).GetRunEvents(context.Background(), "run"); err == nil {
			t.Fatal("expected directory entry to fail ReadFile")
		}
	})

	t.Run("entry parse error", func(t *testing.T) {
		dir := t.TempDir()
		writeReplayTapeManifest(t, dir, nil)
		if err := os.WriteFile(filepath.Join(dir, "entry_0001.json"), []byte("{not-json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewTapeEventSource(dir).GetRunEvents(context.Background(), "run"); err == nil {
			t.Fatal("expected invalid tape entry JSON to fail")
		}
	})

	t.Run("integrity error", func(t *testing.T) {
		dir := t.TempDir()
		entry := replayTapeEntry(1, tape.EntryTypeToolOutput, "tool", "tool-id", []byte("payload"), time.Now().UTC())
		badManifest := &tape.Manifest{
			RunID: "run",
			Entries: []tape.ManifestItem{{
				Seq:       entry.Seq,
				Type:      entry.Type,
				Key:       entry.Key,
				SHA256:    "wrong-hash",
				SizeBytes: int64(len(entry.Value)),
			}},
		}
		writeReplayTapeFixture(t, dir, []tape.Entry{entry}, badManifest)
		if _, err := NewTapeEventSource(dir).GetRunEvents(context.Background(), "run"); err == nil {
			t.Fatal("expected manifest integrity mismatch to fail")
		}
	})
}

func replayTapeEntry(seq uint64, entryType tape.EntryType, componentID, key string, value []byte, timestamp time.Time) tape.Entry {
	sum := sha256.Sum256(value)
	return tape.Entry{
		Seq:             seq,
		Type:            entryType,
		ComponentID:     componentID,
		Key:             key,
		ValueHash:       hex.EncodeToString(sum[:]),
		Value:           value,
		Timestamp:       timestamp,
		DataClass:       "PUBLIC",
		ResidencyRegion: "US",
		Encryption:      "AES-256-GCM",
		RetentionBasis:  "test",
	}
}

func writeReplayTapeFixture(t *testing.T, dir string, entries []tape.Entry, manifest *tape.Manifest) {
	t.Helper()
	for _, entry := range entries {
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "entry_"+zeroPadReplaySeq(entry.Seq)+".json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if manifest == nil {
		manifest = &tape.Manifest{RunID: "run", Entries: make([]tape.ManifestItem, 0, len(entries))}
		for _, entry := range entries {
			manifest.Entries = append(manifest.Entries, tape.ManifestItem{
				Seq:       entry.Seq,
				Type:      entry.Type,
				Key:       entry.Key,
				SHA256:    entry.ValueHash,
				SizeBytes: int64(len(entry.Value)),
			})
		}
	}
	writeReplayTapeManifest(t, dir, manifest)
}

func writeReplayTapeManifest(t *testing.T, dir string, manifest *tape.Manifest) {
	t.Helper()
	if manifest == nil {
		manifest = &tape.Manifest{RunID: "run"}
	}
	if err := tape.WriteManifest(dir, manifest); err != nil {
		t.Fatal(err)
	}
}

func zeroPadReplaySeq(seq uint64) string {
	switch {
	case seq < 10:
		return "000" + strconvFormatReplaySeq(seq)
	case seq < 100:
		return "00" + strconvFormatReplaySeq(seq)
	case seq < 1000:
		return "0" + strconvFormatReplaySeq(seq)
	default:
		return strconvFormatReplaySeq(seq)
	}
}

func strconvFormatReplaySeq(seq uint64) string {
	return strconv.FormatUint(seq, 10)
}
