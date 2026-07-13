package executor

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// OutboxRecord represents an intent to execute an effect.
type OutboxRecord struct {
	ID        string                               `json:"id"`
	Effect    *contracts.Effect                    `json:"effect"`
	Intent    *contracts.AuthorizedExecutionIntent `json:"intent"`
	Scheduled time.Time                            `json:"scheduled"`
	Status    string                               `json:"status"` // PENDING, DONE, FAILED
}

// OutboxClaimState describes the durable disposition of an execution-intent
// reservation. Only Claimed authorizes a ToolDriver invocation.
type OutboxClaimState string

const (
	OutboxClaimed    OutboxClaimState = "CLAIMED"
	OutboxInProgress OutboxClaimState = "IN_PROGRESS"
	OutboxCompleted  OutboxClaimState = "COMPLETED"
	OutboxPending    OutboxClaimState = "PENDING"
)

// OutboxClaimResult is returned by an atomic durable claim. A caller must
// never infer ownership from the absence of an error: an existing claim is a
// normal no-dispatch outcome.
type OutboxClaimResult struct {
	State OutboxClaimState `json:"state"`
}

// OutboxStore defines the transactional persistence layer for effects.
type OutboxStore interface {
	// Claim atomically reserves an intent before any irreversible driver call.
	// Only a result with State == OutboxClaimed permits dispatch.
	Claim(ctx context.Context, effect *contracts.Effect, intent *contracts.AuthorizedExecutionIntent) (OutboxClaimResult, error)
	// GetPending returns all scheduled but not yet executed records.
	GetPending(ctx context.Context) ([]*OutboxRecord, error)
	// MarkDone marks a record as executed (idempotency key).
	MarkDone(ctx context.Context, id string) error
}

// ReceiptStore defines the interface for persisting execution receipts.
type ReceiptStore interface {
	GetByReceiptID(ctx context.Context, receiptID string) (*contracts.Receipt, error)
	// AppendCausal locks a signed session chain, assigns its causal fields, and
	// persists the signed receipt atomically.
	AppendCausal(ctx context.Context, sessionID string, build func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error)) error
}

// MCPClient defines the interface for interacting with the Managed Capability Platform.
// Kept for backward compatibility if needed, but ToolDriver is preferred.
type MCPClient interface {
	Call(tool string, params map[string]any) (any, error)
}
