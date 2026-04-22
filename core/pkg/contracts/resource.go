package contracts

import (
	"context"
	"time"
)

// ResourceCost defines the cost of an operation.
type ResourceCost struct {
	Compute      float64 `json:"compute"`
	ComputeUnits float64 `json:"compute_units"` // Alias
	StorageBytes int64   `json:"storage_bytes"`
	NetworkBytes int64   `json:"network_bytes"`
	Money        float64 `json:"money,omitempty"`  // Legacy field
	Amount       float64 `json:"amount,omitempty"` // Legacy wrapper
	Currency     string  `json:"currency,omitempty"`

	// Legacy
	Time     time.Duration `json:"time,omitempty"`
	APIQuota int           `json:"api_quota,omitempty"`
}

// ReceiptSink defines an interface for components that accept receipts.
type ReceiptSink interface {
	SubmitReceipt(ctx context.Context, receipt Receipt) error
}

// Receipt defined in effect_receipt.go or alias here?
// We used EffectReceipt in `effect_receipt.go`.
// To allow `SubmitReceipt(ctx any, receipt Receipt)` compat, we might need alias.
// But better to switch sinks to `EffectReceipt`.

// ResourceDef defines a resource type.
type ResourceDef struct {
	Name   string `json:"name"`
	Schema string `json:"schema"` // JSON Schema or ref
}
