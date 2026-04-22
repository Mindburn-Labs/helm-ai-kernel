package conform

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PanicRecord is the minimal record emitted when the receipt system fails.
// Per §receipt-emission-failure: if receipts cannot be emitted, the runtime
// MUST halt and emit a panic record to an immutable local sink.
// helm conform MUST FAIL with RECEIPT_EMISSION_PANIC.
type PanicRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	RunID       string    `json:"run_id"`
	TenantID    string    `json:"tenant_id"`
	Reason      string    `json:"reason"`
	LastGoodSeq uint64    `json:"last_good_seq"`
	ErrorDetail string    `json:"error_detail"`
}

// PanicSinkPath returns the immutable local path for panic records.
func PanicSinkPath(evidenceDir string) string {
	return filepath.Join(evidenceDir, "06_LOGS", "receipt_emission_panic.json")
}

// WritePanicRecord writes a panic record to the immutable local sink.
// This MUST succeed even when the receipt system is broken — it uses
// direct file I/O with no dependencies on the receipt pipeline.
func WritePanicRecord(evidenceDir string, record *PanicRecord) error {
	sinkPath := PanicSinkPath(evidenceDir)
	_ = os.MkdirAll(filepath.Dir(sinkPath), 0750)

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal panic record: %w", err)
	}

	// Write atomically: write to temp, then rename
	tmpPath := sinkPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		// Last resort: write directly
		return os.WriteFile(sinkPath, data, 0600)
	}
	return os.Rename(tmpPath, sinkPath)
}

// CheckPanicRecord returns the panic record if one exists, or nil.
func CheckPanicRecord(evidenceDir string) (*PanicRecord, error) {
	sinkPath := PanicSinkPath(evidenceDir)
	data, err := os.ReadFile(sinkPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no panic — good
		}
		return nil, err
	}

	var record PanicRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("corrupt panic record: %w", err)
	}
	return &record, nil
}
