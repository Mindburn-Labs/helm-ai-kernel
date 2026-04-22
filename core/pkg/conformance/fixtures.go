// Package conformance provides test fixtures for conformance verification.
package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ── Receipt fixtures ─────────────────────────────────────────

// receiptEntry is a simplified receipt for chain verification.
type receiptEntry struct {
	Hash     string
	PrevHash string
	Lamport  uint64
}

// sampleReceiptChain returns a valid 5-entry receipt hash chain.
func sampleReceiptChain() []receiptEntry {
	chain := make([]receiptEntry, 5)
	prevHash := ""
	for i := 0; i < 5; i++ {
		data := fmt.Sprintf("receipt-%d-%s", i, prevHash)
		h := sha256.Sum256([]byte(data))
		hash := "sha256:" + hex.EncodeToString(h[:])
		chain[i] = receiptEntry{
			Hash:     hash,
			PrevHash: prevHash,
			Lamport:  uint64(i + 1),
		}
		prevHash = hash
	}
	return chain
}

// ── Trust event fixtures ─────────────────────────────────────

// trustEventEntry is a simplified trust event for chain verification.
type trustEventEntry struct {
	Hash     string
	PrevHash string
	Lamport  uint64
}

// sampleTrustEventChain returns a valid 5-entry trust event hash chain.
func sampleTrustEventChain() []trustEventEntry {
	chain := make([]trustEventEntry, 5)
	prevHash := ""
	for i := 0; i < 5; i++ {
		data := fmt.Sprintf("trust-event-%d-%s", i, prevHash)
		h := sha256.Sum256([]byte(data))
		hash := "sha256:" + hex.EncodeToString(h[:])
		chain[i] = trustEventEntry{
			Hash:     hash,
			PrevHash: prevHash,
			Lamport:  uint64(i + 1),
		}
		prevHash = hash
	}
	return chain
}

// ── Evidence pack fixtures ───────────────────────────────────

// evidencePackEntry represents a single entry in an evidence pack manifest.
type evidencePackEntry struct {
	Path string
	Hash string
}

// evidencePack is a simplified evidence pack for manifest verification.
type evidencePack struct {
	ManifestHash string
	Entries      []evidencePackEntry
}

// sampleEvidencePack returns a valid evidence pack with correct manifest hash.
func sampleEvidencePack() evidencePack {
	entries := []evidencePackEntry{
		{Path: "receipts/001.json", Hash: "sha256:aaa111"},
		{Path: "receipts/002.json", Hash: "sha256:bbb222"},
		{Path: "trust/events.json", Hash: "sha256:ccc333"},
	}
	return evidencePack{
		ManifestHash: computeManifestHash(entries),
		Entries:      entries,
	}
}

// computeManifestHash computes a deterministic hash over sorted manifest entries.
func computeManifestHash(entries []evidencePackEntry) string {
	// Sort entries by path for deterministic ordering
	sorted := make([]evidencePackEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})

	var parts []string
	for _, e := range sorted {
		parts = append(parts, e.Path+":"+e.Hash)
	}
	canonical := strings.Join(parts, "\n")
	h := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(h[:])
}

// ── Replay fixtures ──────────────────────────────────────────

// replayAndHash replays a chain of trust events and returns a deterministic hash.
func replayAndHash(events []trustEventEntry) string {
	// Deterministic replay: hash all event hashes in order
	h := sha256.New()
	for _, e := range events {
		h.Write([]byte(e.Hash))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ── Drift fixtures ───────────────────────────────────────────

// driftResult represents the outcome of a drift check.
type driftResult struct {
	Detected    bool
	ConnectorID string
}

// simulateConnectorDrift simulates a connector schema drift scenario.
func simulateConnectorDrift() driftResult {
	return driftResult{
		Detected:    true,
		ConnectorID: "stripe-payments-v2",
	}
}
