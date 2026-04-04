package scheduler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// DispatchReceipt is the immutable record created when a trigger is dispatched.
// It provides an audit trail and a content hash for tamper detection.
type DispatchReceipt struct {
	// ReceiptID is a globally unique identifier for this receipt.
	ReceiptID string `json:"receipt_id"`
	// ScheduleID identifies the schedule that generated the trigger.
	ScheduleID string `json:"schedule_id"`
	// FireAtUnixMs is the nominal fire time in milliseconds since Unix epoch.
	FireAtUnixMs int64 `json:"fire_at_unix_ms"`
	// DispatchedAt is the wall-clock time at which the receipt was created (Unix ms).
	DispatchedAt int64 `json:"dispatched_at_unix_ms"`
	// IdempotencyKey is the unique key used to deduplicate the dispatch.
	IdempotencyKey string `json:"idempotency_key"`
	// ContentHash is the SHA-256 hex digest of the canonical JSON representation
	// of {receipt_id, schedule_id, fire_at_unix_ms, idempotency_key}.
	ContentHash string `json:"content_hash"`
}

// NewDispatchReceipt creates a DispatchReceipt from a TriggerDecision.
// ReceiptID is generated as a new UUIDv4. ContentHash covers the stable fields.
func NewDispatchReceipt(decision TriggerDecision) *DispatchReceipt {
	r := &DispatchReceipt{
		ReceiptID:      uuid.New().String(),
		ScheduleID:     decision.ScheduleID,
		FireAtUnixMs:   decision.FireAtUnixMs,
		DispatchedAt:   time.Now().UnixMilli(),
		IdempotencyKey: decision.IdempotencyKey,
	}
	r.ContentHash = computeContentHash(r)
	return r
}

// hashPayload is the subset of DispatchReceipt fields included in the content hash.
// This excludes DispatchedAt (wall-clock) and ContentHash itself to keep the hash stable.
type hashPayload struct {
	ReceiptID      string `json:"receipt_id"`
	ScheduleID     string `json:"schedule_id"`
	FireAtUnixMs   int64  `json:"fire_at_unix_ms"`
	IdempotencyKey string `json:"idempotency_key"`
}

// computeContentHash returns the SHA-256 hex digest of the canonical JSON of the
// stable fields in r. Panics only on impossible json.Marshal failures.
func computeContentHash(r *DispatchReceipt) string {
	p := hashPayload{
		ReceiptID:      r.ReceiptID,
		ScheduleID:     r.ScheduleID,
		FireAtUnixMs:   r.FireAtUnixMs,
		IdempotencyKey: r.IdempotencyKey,
	}
	data, err := json.Marshal(p)
	if err != nil {
		// json.Marshal on a plain struct with primitive fields cannot fail.
		panic(fmt.Sprintf("scheduler: computeContentHash: %v", err))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
