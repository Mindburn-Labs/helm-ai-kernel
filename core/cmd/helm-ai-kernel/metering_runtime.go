package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/metering"
)

type meteringReservation struct {
	client          metering.Client
	subject         metering.Subject
	authorizationID string
}

func meteringEnabled(svc *Services) bool {
	return svc != nil && svc.Metering != nil && svc.Metering.Enabled()
}

// verifiedMeteringSubject takes tenant and principal only from the authenticated
// request context. Workspace is accepted only when it exactly matches the
// server-owned binding, so caller headers cannot select a billable scope.
func verifiedMeteringSubject(r *http.Request) (metering.Subject, error) {
	principal, err := helmauth.GetPrincipal(r.Context())
	if err != nil || principal == nil {
		return metering.Subject{}, fmt.Errorf("metering requires authenticated tenant principal context")
	}
	workspaceID := strings.TrimSpace(r.Header.Get(workspaceHeader))
	configuredTenantID := strings.TrimSpace(os.Getenv(runtimeTenantIDEnv))
	configuredPrincipalID := runtimePrincipalID()
	configuredWorkspaceID := configuredRuntimeWorkspaceID()
	if configuredTenantID == "" || configuredPrincipalID == "" || configuredWorkspaceID == "" {
		return metering.Subject{}, fmt.Errorf("metering requires explicit server-owned tenant, workspace, and principal bindings")
	}
	if workspaceID != configuredWorkspaceID {
		return metering.Subject{}, fmt.Errorf("metering requires a verified server-bound workspace")
	}
	subject := metering.Subject{
		TenantID:    strings.TrimSpace(principal.GetTenantID()),
		WorkspaceID: workspaceID,
		PrincipalID: strings.TrimSpace(principal.GetID()),
	}
	if err := subject.Validate(); err != nil {
		return metering.Subject{}, err
	}
	if subject.TenantID != configuredTenantID || subject.PrincipalID != configuredPrincipalID {
		return metering.Subject{}, fmt.Errorf("metering request identity does not match the server-owned binding")
	}
	return subject, nil
}

func runtimeMeteringSubject() (metering.Subject, error) {
	subject := metering.Subject{
		TenantID:    strings.TrimSpace(os.Getenv(runtimeTenantIDEnv)),
		WorkspaceID: configuredRuntimeWorkspaceID(),
		PrincipalID: strings.TrimSpace(runtimePrincipalID()),
	}
	if err := subject.Validate(); err != nil {
		return metering.Subject{}, err
	}
	return subject, nil
}

func runtimePrincipalID() string {
	return strings.TrimSpace(os.Getenv(runtimePrincipalIDEnv))
}

// reserveMetering creates a receipt-bound permit before an ingress dispatches
// an externally observable effect. The control plane, not the ingress, derives
// charge class and credits from the verified receipt.
func reserveMetering(ctx context.Context, svc *Services, subject metering.Subject, ingress, decisionReceiptID string) (*meteringReservation, error) {
	if !meteringEnabled(svc) {
		return nil, nil
	}
	return reserveMeteringClient(ctx, svc.Metering, subject, ingress, decisionReceiptID)
}

func reserveMeteringClient(ctx context.Context, client metering.Client, subject metering.Subject, ingress, decisionReceiptID string) (*meteringReservation, error) {
	if client == nil || !client.Enabled() {
		return nil, nil
	}
	authorization, err := client.Authorize(ctx, metering.AuthorizationRequest{
		Subject:           subject,
		Ingress:           ingress,
		DecisionReceiptID: decisionReceiptID,
	})
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(authorization.AuthorizationID) == "" {
		return nil, fmt.Errorf("hosted metering authorization did not return an authorization id")
	}
	return &meteringReservation{client: client, subject: subject, authorizationID: authorization.AuthorizationID}, nil
}

// settle records the receipt that closes the authorization. A receipt ID is
// required so the control plane can derive the actual charge from source-owned
// evidence rather than caller-provided outcomes or unit counts.
func (r *meteringReservation) settle(ctx context.Context, settlementReceiptID string) error {
	if r == nil {
		return nil
	}
	_, err := r.client.Settle(ctx, metering.SettlementRequest{
		Subject:             r.subject,
		AuthorizationID:     r.authorizationID,
		SettlementReceiptID: settlementReceiptID,
	})
	return err
}

// decisionMeteringLifecycle exists only to make the source-owned commercial
// catalogue explicit at this boundary. It is never serialized or trusted for
// billing: the control plane recomputes the class and credits from receipts.
type decisionMeteringLifecycle struct {
	Class     string
	Credits   int64
	SettleNow bool
}

func meteringLifecycleForVerdict(verdict string) decisionMeteringLifecycle {
	switch contracts.Verdict(verdict) {
	case contracts.VerdictAllow:
		return decisionMeteringLifecycle{Class: "routine_allow", Credits: 0, SettleNow: true}
	case contracts.VerdictDeny:
		return decisionMeteringLifecycle{Class: "deny", Credits: 1, SettleNow: true}
	case contracts.VerdictEscalate:
		// An ESCALATE is a zero-credit routing state. A separate, durable
		// approval-ceremony receipt reserves and settles the one 10-credit
		// approval_ceremony event when that ceremony is actually begun/completed.
		return decisionMeteringLifecycle{Class: "escalate", Credits: 0, SettleNow: false}
	default:
		// Fail closed in the catalogue: an unknown terminal decision is
		// accounted as a DENY once a receipt has been verified.
		return decisionMeteringLifecycle{Class: "deny", Credits: 1, SettleNow: true}
	}
}
