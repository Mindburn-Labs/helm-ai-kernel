package contracts

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestApprovalDispatchAdmissionSealsAndBindsConsumption(t *testing.T) {
	consumption := approvalDispatchAdmissionConsumption(t)
	issuedAt := consumption.ConsumedAt.Add(time.Second)
	admission, err := (ApprovalDispatchAdmission{
		SchemaVersion: ApprovalDispatchAdmissionSchemaV1, ContractVersion: ApprovalDispatchAdmissionContractV1,
		Coverage:    ApprovalDispatchAdmissionCoverageV1,
		AdmissionID: "dispatch-admission-a", AttemptID: "attempt-a", State: ApprovalDispatchAdmissionStateV1,
		ApprovalID: consumption.ApprovalID, GrantID: consumption.GrantID,
		GrantHash: consumption.GrantHash, ConsumptionHash: consumption.ConsumptionHash,
		TenantID: consumption.TenantID, WorkspaceID: consumption.WorkspaceID,
		Audience: consumption.Audience, AdmittedBy: consumption.ConsumedBy,
		IdempotencyKeyHash: approvalGrantSHA("b"), EffectHash: consumption.EffectHash,
		ConnectorID: "connector-a", Action: consumption.Action,
		KernelTrustRootID: consumption.KernelTrustRootID, SigningKeyRef: consumption.SigningKeyRef,
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(30 * time.Second),
	}).Seal()
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	if err := admission.ValidateConsumption(consumption); err != nil {
		t.Fatalf("ValidateConsumption(): %v", err)
	}
	if err := admission.ValidateAt(admission.IssuedAt); err != nil {
		t.Fatalf("ValidateAt(issued_at): %v", err)
	}
	if err := admission.ValidateAt(admission.ExpiresAt.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("ValidateAt(before expires_at): %v", err)
	}
	for name, now := range map[string]time.Time{
		"before issued": admission.IssuedAt.Add(-time.Nanosecond),
		"at expiry":     admission.ExpiresAt,
		"after expiry":  admission.ExpiresAt.Add(time.Nanosecond),
	} {
		t.Run(name, func(t *testing.T) {
			if err := admission.ValidateAt(now); !errors.Is(err, ErrApprovalDispatchAdmissionInactive) {
				t.Fatalf("ValidateAt(%s) error = %v, want inactive", now, err)
			}
		})
	}

	tampered := admission
	tampered.ConnectorID = "connector-b"
	if err := tampered.ValidateConsumption(consumption); err == nil {
		t.Fatal("tampered admission must fail")
	}
	tampered = admission
	tampered.ExpiresAt = consumption.GrantExpiresAt.Add(time.Second)
	if err := tampered.ValidateConsumption(consumption); err == nil {
		t.Fatal("admission beyond grant expiry must fail")
	}
}

func TestApprovalDispatchAdmissionRejectsInvalidShape(t *testing.T) {
	consumption := approvalDispatchAdmissionConsumption(t)
	issuedAt := consumption.ConsumedAt.Add(time.Second)
	base := ApprovalDispatchAdmission{
		SchemaVersion: ApprovalDispatchAdmissionSchemaV1, ContractVersion: ApprovalDispatchAdmissionContractV1,
		Coverage:    ApprovalDispatchAdmissionCoverageV1,
		AdmissionID: "dispatch-admission-a", AttemptID: "attempt-a", State: ApprovalDispatchAdmissionStateV1,
		ApprovalID: consumption.ApprovalID, GrantID: consumption.GrantID,
		GrantHash: consumption.GrantHash, ConsumptionHash: consumption.ConsumptionHash,
		TenantID: consumption.TenantID, WorkspaceID: consumption.WorkspaceID,
		Audience: consumption.Audience, AdmittedBy: consumption.ConsumedBy,
		IdempotencyKeyHash: approvalGrantSHA("b"), EffectHash: consumption.EffectHash,
		ConnectorID: "connector-a", Action: consumption.Action,
		KernelTrustRootID: consumption.KernelTrustRootID, SigningKeyRef: consumption.SigningKeyRef,
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(30 * time.Second),
	}
	tests := map[string]func(*ApprovalDispatchAdmission){
		"whitespace attempt": func(a *ApprovalDispatchAdmission) { a.AttemptID = "attempt a" },
		"overlong attempt":   func(a *ApprovalDispatchAdmission) { a.AttemptID = strings.Repeat("a", 513) },
		"bad hash":           func(a *ApprovalDispatchAdmission) { a.IdempotencyKeyHash = "sha256:no" },
		"overlong ttl":       func(a *ApprovalDispatchAdmission) { a.ExpiresAt = a.IssuedAt.Add(time.Minute + time.Nanosecond) },
		"bad action":         func(a *ApprovalDispatchAdmission) { a.Action = "execute" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if _, err := candidate.Seal(); err == nil {
				t.Fatal("invalid admission sealed")
			}
		})
	}
}

func approvalDispatchAdmissionConsumption(t *testing.T) ApprovalGrantConsumption {
	t.Helper()
	issuedAt := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	consumption, err := (ApprovalGrantConsumption{
		SchemaVersion: ApprovalGrantConsumptionSchemaV1, ContractVersion: ApprovalGrantConsumptionContractV1,
		ApprovalID: "approval-a", GrantID: "grant-a", GrantHash: approvalGrantSHA("a"),
		TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: "packs.lifecycle", ConsumedBy: "spiffe://helm/data-plane-a",
		PackID: "pack-a", PackVersion: "1.0.0", PackManifestHash: approvalGrantSHA("c"), Action: ApprovalGrantActionInstall,
		IntentHash: approvalGrantSHA("d"), EffectHash: approvalGrantSHA("e"), PlanHash: approvalGrantSHA("f"),
		PolicyVersion: "policy-v1", PolicyEpoch: "epoch-1", PolicyHash: approvalGrantSHA("1"),
		ServerIdentity: "spiffe://helm/kernel-a", KernelTrustRootID: "kernel-root-1", SigningKeyRef: "kernel-key-1",
		GrantIssuedAt: issuedAt, GrantExpiresAt: issuedAt.Add(5 * time.Minute), ConsumedAt: issuedAt.Add(time.Minute),
	}).Seal()
	if err != nil {
		t.Fatalf("seal consumption: %v", err)
	}
	return consumption
}

func approvalGrantSHA(value string) string {
	return "sha256:" + strings.Repeat(value, 64)
}
