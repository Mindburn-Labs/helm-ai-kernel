package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/interfaces"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/manifest"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/safedep"
)

// UsageMeter is an optional interface for recording execution usage events.
// Implementations may be injected for commercial metering; the canonical
// standard operates correctly with a nil meter.
type UsageMeter interface {
	Record(ctx context.Context, event UsageEvent) error
}

// UsageEvent represents an execution usage event for optional metering.
type UsageEvent struct {
	TenantID  string         `json:"tenant_id"`
	EventType string         `json:"event_type"`
	Quantity  int64          `json:"quantity"`
	Timestamp time.Time      `json:"timestamp"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// Executor runs an effect if and only if it has a valid, notarized decision AND an execution intent.
type Executor interface {
	Execute(ctx context.Context, effect *contracts.Effect, decision *contracts.DecisionRecord, intent *contracts.AuthorizedExecutionIntent) (*contracts.Receipt, *interfaces.Artifact, error)
}

// OutputSchemaRegistry provides tool output schemas for drift detection.
type OutputSchemaRegistry interface {
	LookupOutput(toolName string) *manifest.ToolOutputSchema
}

type SafeDepGate interface {
	Gate(ctx context.Context, req safedep.GateRequest) (safedep.GateResult, error)
}

// ReceiptIDForDecision returns the deterministic receipt identity for a
// decision. Authenticated tenant executions must not share a globally unique
// receipt ID merely because their decision IDs happen to match.
func ReceiptIDForDecision(tenantID, decisionID string) string {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return "rcpt-" + decisionID
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%d:%s%d:%s", len(tenantID), tenantID, len(decisionID), decisionID)))
	return "rcpt-" + hex.EncodeToString(digest[:])
}

// Match interfaces for compiler output
type CompilerPolicy interface {
	GetProhibitedTools() []string
}
