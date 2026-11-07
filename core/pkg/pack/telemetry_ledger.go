package pack

import (
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
