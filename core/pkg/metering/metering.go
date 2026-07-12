// Package metering defines the transport-neutral hosted metering contract.
// Local and OSS callers use the disabled client, which performs no network IO.
package metering

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	IngressEvaluate    = "api.evaluate"
	IngressOpenAIProxy = "openai.proxy"
	IngressMCP         = "mcp.gateway"
	IngressCLIProxy    = "cli.proxy"
)

// Subject is a verified execution identity. Its values must come from the
// authenticated transport or server-owned runtime configuration, never caller
// pricing headers or request JSON. It is deliberately excluded from both the
// JSON body and transport headers; the control plane derives scope from the
// validated service bearer while the kernel uses Subject as a local binding
// check before it makes a hosted call.
type Subject struct {
	TenantID    string `json:"-"`
	WorkspaceID string `json:"-"`
	PrincipalID string `json:"-"`
}

func (s Subject) Validate() error {
	if strings.TrimSpace(s.TenantID) == "" {
		return fmt.Errorf("metering tenant_id is required")
	}
	if strings.TrimSpace(s.WorkspaceID) == "" {
		return fmt.Errorf("metering workspace_id is required")
	}
	if strings.TrimSpace(s.PrincipalID) == "" {
		return fmt.Errorf("metering principal_id is required")
	}
	return nil
}

// NewIngressReceiptID reserves a receipt correlation ID before dispatch. The
// ingress must use this same ID when it writes the decision or settlement
// receipt that the control plane verifies.
func NewIngressReceiptID(ingress string) (string, error) {
	if strings.TrimSpace(ingress) == "" {
		return "", fmt.Errorf("metering ingress is required for receipt id")
	}
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate metering receipt id: %w", err)
	}
	return "rcpt_" + strings.ReplaceAll(ingress, ".", "_") + "_" + hex.EncodeToString(bytes), nil
}

// AuthorizationRequest is sent before an externally observable dispatch.
// The body is intentionally limited to the ingress and a decision receipt ID.
// Charge class, credits, value, connector attestation, OEM participation, and
// pricing version are all derived and verified by the control plane.
type AuthorizationRequest struct {
	Subject           Subject `json:"-"`
	Ingress           string  `json:"ingress"`
	DecisionReceiptID string  `json:"decision_receipt_id"`
}

func (r AuthorizationRequest) Validate() error {
	if err := r.Subject.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(r.Ingress) == "" {
		return fmt.Errorf("metering ingress is required")
	}
	if strings.TrimSpace(r.DecisionReceiptID) == "" {
		return fmt.Errorf("metering decision_receipt_id is required")
	}
	return nil
}

// Authorization is the control-plane permit for the verified decision
// receipt. AuthorizationID is server-issued and binds the later settlement to
// this permit; it is never selected by the ingress or caller.
type Authorization struct {
	AuthorizationID string `json:"authorization_id"`
	Approved        bool   `json:"approved"`
}

// SettlementRequest records a completed receipt after the effect, refusal, or
// approval ceremony is complete. AuthorizationID is server-issued by the
// prior authorization; callers cannot select a class, quantity, price,
// monetary value, or OEM share.
type SettlementRequest struct {
	Subject             Subject `json:"-"`
	AuthorizationID     string  `json:"authorization_id"`
	SettlementReceiptID string  `json:"settlement_receipt_id"`
}

func (r SettlementRequest) Validate() error {
	if err := r.Subject.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(r.AuthorizationID) == "" {
		return fmt.Errorf("metering authorization_id is required")
	}
	if strings.TrimSpace(r.SettlementReceiptID) == "" {
		return fmt.Errorf("metering settlement_receipt_id is required")
	}
	return nil
}

type Settlement struct {
	SettlementID string `json:"settlement_id"`
	Settled      bool   `json:"settled"`
}

// Client is deliberately small so every ingress uses the same pre-dispatch
// authorization and post-receipt settlement protocol.
type Client interface {
	Enabled() bool
	Authorize(context.Context, AuthorizationRequest) (Authorization, error)
	Settle(context.Context, SettlementRequest) (Settlement, error)
}

// Disabled is the OSS/local default. It has no side effects and callers must
// skip all hosted-metering calls when Enabled reports false.
type Disabled struct{}

func (Disabled) Enabled() bool { return false }

func (Disabled) Authorize(context.Context, AuthorizationRequest) (Authorization, error) {
	return Authorization{}, fmt.Errorf("hosted metering is disabled")
}

func (Disabled) Settle(context.Context, SettlementRequest) (Settlement, error) {
	return Settlement{}, fmt.Errorf("hosted metering is disabled")
}
