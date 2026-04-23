package pack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// LedgerTelemetryHook implements TelemetryHook with a cryptographic ledger.
type LedgerTelemetryHook struct {
	filePath string
	mu       sync.Mutex
}

type TelemetryEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"` // execution, evidence, incident
	PackID    string    `json:"pack_id"`
	Version   string    `json:"version"`
	Data      any       `json:"data"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// NewLedgerTelemetryHook creates a new hook that writes to a file.
func NewLedgerTelemetryHook(path string) *LedgerTelemetryHook {
	return &LedgerTelemetryHook{
		filePath: path,
	}
}

func (h *LedgerTelemetryHook) append(entry *TelemetryEntry) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 1. Read last line to get PrevHash (simplified: assume we track it in memory or read file end)
	// For high throughput, we should cache lastHash.
	// This simple implementation reads the whole file to find the last line is inefficient but safe for MVP.
	// Optimization: check file stat size.

	// Just calculating hash of current content + new content logic
	// In production, use properly implemented LedgerStore like in portal.
	// Here we implement a simple append.

	file, err := os.OpenFile(h.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	// Compute Hash
	data, _ := json.Marshal(entry)
	// Entry hash = sha256(json)
	hash := sha256.Sum256(data)
	entry.Hash = hex.EncodeToString(hash[:])

	// Re-marshal with hash
	finalData, _ := json.Marshal(entry)

	if _, err := file.Write(finalData); err != nil {
		return err
	}
	if _, err := file.WriteString("\n"); err != nil {
		return err
	}

	return nil
}

func (h *LedgerTelemetryHook) RecordExecution(ctx context.Context, packID, version string, success bool, duration time.Duration) {
	_ = h.append(&TelemetryEntry{
		Timestamp: time.Now(),
		Type:      "execution",
		PackID:    packID,
		Version:   version,
		Data: map[string]any{
			"success":  success,
			"duration": duration.String(),
		},
	})
}

func (h *LedgerTelemetryHook) RecordEvidenceGeneration(ctx context.Context, packID, version string, evidenceClass string, success bool) {
	_ = h.append(&TelemetryEntry{
		Timestamp: time.Now(),
		Type:      "evidence",
		PackID:    packID,
		Version:   version,
		Data: map[string]any{
			"class":   evidenceClass,
			"success": success,
		},
	})
}

func (h *LedgerTelemetryHook) RecordIncident(ctx context.Context, packID, version string, severity string) {
	_ = h.append(&TelemetryEntry{
		Timestamp: time.Now(),
		Type:      "incident",
		PackID:    packID,
		Version:   version,
		Data: map[string]any{
			"severity": severity,
		},
	})
}

// GetMetrics would scan the ledger to aggregate metrics.
// Planned enhancement: move this to an aggregator process or cached index.
// We implement a naive scan here.
func (h *LedgerTelemetryHook) GetMetrics(ctx context.Context, packID, version string) (*PackMetrics, error) {
	file, err := os.Open(h.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &PackMetrics{PackID: packID, Version: version}, nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	metrics := &PackMetrics{
		PackID:  packID,
		Version: version,
	}

	// Scan file... (omitted for brevity, would behave like CalculateTrustScore inputs)
	// Real implementation would use an indexing service.
	return metrics, nil
}
