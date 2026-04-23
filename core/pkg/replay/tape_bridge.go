package replay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/tape"
)

// TapeEventSource adapts VCR tape entries into replay RunEvents,
// unifying the tape and replay packages around a shared data model.
//
// This bridges the gap between the conformance-layer tape recorder
// (which captures nondeterministic inputs) and the runtime-layer
// replay engine (which re-executes them).
type TapeEventSource struct {
	tapesDir string
}

// NewTapeEventSource creates an EventSource that reads from the tape
// directory structure (08_TAPES/).
func NewTapeEventSource(tapesDir string) *TapeEventSource {
	return &TapeEventSource{tapesDir: tapesDir}
}

// GetRunEvents loads tape entries and manifest from the tapes directory,
// then converts them to RunEvents suitable for the replay engine.
func (s *TapeEventSource) GetRunEvents(_ context.Context, _ string) ([]RunEvent, error) {
	manifest, err := tape.ReadManifest(s.tapesDir)
	if err != nil {
		return nil, fmt.Errorf("read tape manifest: %w", err)
	}

	entries, err := LoadTapeEntries(s.tapesDir)
	if err != nil {
		return nil, fmt.Errorf("load tape entries: %w", err)
	}

	// Verify integrity before converting
	issues := tape.VerifyManifestIntegrity(entries, manifest)
	if len(issues) > 0 {
		return nil, fmt.Errorf("tape integrity check failed: %v", issues)
	}

	events := make([]RunEvent, len(entries))
	for i, entry := range entries {
		events[i] = TapeEntryToRunEvent(entry)
	}

	return events, nil
}

// TapeEntryToRunEvent converts a tape.Entry to a replay.RunEvent.
//
// Field mapping:
//
//	tape.Entry.Seq         → RunEvent.SequenceNumber
//	tape.Entry.Type        → RunEvent.EventType
//	tape.Entry.ComponentID → RunEvent.EventID
//	tape.Entry.ValueHash   → RunEvent.PayloadHash
//	tape.Entry.ValueHash   → RunEvent.OutputHash (for VCR: input IS output)
//	tape.Entry.Key         → RunEvent.PRNGSeed (when Type == RNG_SEED)
//	tape.Entry.Timestamp   → RunEvent.Timestamp
func TapeEntryToRunEvent(entry tape.Entry) RunEvent {
	event := RunEvent{
		SequenceNumber: entry.Seq,
		EventID:        entry.ComponentID,
		EventType:      string(entry.Type),
		PayloadHash:    entry.ValueHash,
		OutputHash:     entry.ValueHash,
		Timestamp:      entry.Timestamp,
	}

	// Map RNG seed entries
	if entry.Type == tape.EntryTypeRNGSeed {
		event.PRNGSeed = entry.Key
	}

	// Payload from tape value (if present)
	if len(entry.Value) > 0 {
		event.Payload = map[string]interface{}{
			"tape_value":       string(entry.Value),
			"data_class":       entry.DataClass,
			"residency_region": entry.ResidencyRegion,
			"encryption":       entry.Encryption,
			"retention_basis":  entry.RetentionBasis,
		}
	}

	return event
}

// RunEventToTapeEntry converts a replay.RunEvent back to a tape.Entry.
// This enables replay results to be recorded back into the tape format.
func RunEventToTapeEntry(event RunEvent) tape.Entry {
	entry := tape.Entry{
		Seq:         event.SequenceNumber,
		Type:        tape.EntryType(event.EventType),
		ComponentID: event.EventID,
		ValueHash:   event.PayloadHash,
		Timestamp:   event.Timestamp,
	}

	if event.PRNGSeed != "" {
		entry.Key = event.PRNGSeed
	}

	// Extract tape-specific fields from payload
	if event.Payload != nil {
		if v, ok := event.Payload["data_class"].(string); ok {
			entry.DataClass = v
		}
		if v, ok := event.Payload["residency_region"].(string); ok {
			entry.ResidencyRegion = v
		}
		if v, ok := event.Payload["encryption"].(string); ok {
			entry.Encryption = v
		}
		if v, ok := event.Payload["retention_basis"].(string); ok {
			entry.RetentionBasis = v
		}
	}

	return entry
}

// LoadTapeEntries loads tape entries from entry_*.json files in a directory.
func LoadTapeEntries(tapesDir string) ([]tape.Entry, error) {
	files, err := filepath.Glob(filepath.Join(tapesDir, "entry_*.json"))
	if err != nil {
		return nil, fmt.Errorf("glob tape entries: %w", err)
	}

	var entries []tape.Entry
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", filepath.Base(f), err)
		}
		var entry tape.Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, fmt.Errorf("parse %s: %w", filepath.Base(f), err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// ComputeTapeRunHash computes a deterministic hash over tape entries,
// compatible with the replay engine's computeRunHash format.
func ComputeTapeRunHash(entries []tape.Entry) (string, error) {
	hashable := make([]string, len(entries))
	for i, e := range entries {
		hashable[i] = e.ValueHash
	}
	data, err := json.Marshal(hashable)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
