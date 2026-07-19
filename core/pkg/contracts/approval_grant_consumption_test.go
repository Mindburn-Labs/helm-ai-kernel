package contracts

import (
	"errors"
	"testing"
	"time"
)

func TestApprovalGrantConsumptionSealsExactGrantAndWorkload(t *testing.T) {
	grant, err := validApprovalGrant().Seal()
	if err != nil {
		t.Fatal(err)
	}
	base := validApprovalGrantConsumption(grant)
	sealed, err := base.Seal()
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if err := sealed.ValidateGrant(grant); err != nil {
		t.Fatalf("ValidateGrant() error = %v", err)
	}
	sealedAgain, err := sealed.Seal()
	if err != nil || sealedAgain.ConsumptionHash != sealed.ConsumptionHash {
		t.Fatalf("deterministic Seal() = %+v, %v", sealedAgain, err)
	}

	mutations := map[string]struct {
		mutate             func(*ApprovalGrantConsumption)
		breaksGrantBinding bool
	}{
		"consumer":   {mutate: func(c *ApprovalGrantConsumption) { c.ConsumedBy = "spiffe://helm/data-plane-b" }},
		"audience":   {mutate: func(c *ApprovalGrantConsumption) { c.Audience = "packs.lifecycle.other" }, breaksGrantBinding: true},
		"grant hash": {mutate: func(c *ApprovalGrantConsumption) { c.GrantHash = sha256Ref("9") }, breaksGrantBinding: true},
		"effect":     {mutate: func(c *ApprovalGrantConsumption) { c.EffectHash = sha256Ref("8") }, breaksGrantBinding: true},
		"action":     {mutate: func(c *ApprovalGrantConsumption) { c.Action = ApprovalGrantActionUninstall }, breaksGrantBinding: true},
		"time":       {mutate: func(c *ApprovalGrantConsumption) { c.ConsumedAt = c.ConsumedAt.Add(time.Second) }},
	}
	for name, test := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := base
			test.mutate(&candidate)
			candidate, err = candidate.Seal()
			if err != nil {
				t.Fatalf("Seal() error = %v", err)
			}
			if candidate.ConsumptionHash == sealed.ConsumptionHash {
				t.Fatal("authority mutation did not change consumption hash")
			}
			err = candidate.ValidateGrant(grant)
			if test.breaksGrantBinding && !errors.Is(err, ErrApprovalGrantIntegrity) {
				t.Fatalf("ValidateGrant() error = %v, want ErrApprovalGrantIntegrity", err)
			}
			if !test.breaksGrantBinding && err != nil {
				t.Fatalf("ValidateGrant() error = %v", err)
			}
		})
	}
}

func TestApprovalGrantConsumptionRejectsExpiredOrUnsealedRecords(t *testing.T) {
	grant, err := validApprovalGrant().Seal()
	if err != nil {
		t.Fatal(err)
	}
	consumption := validApprovalGrantConsumption(grant)
	if err := consumption.ValidateGrant(grant); !errors.Is(err, ErrApprovalGrantIntegrity) {
		t.Fatalf("unsealed ValidateGrant() error = %v, want ErrApprovalGrantIntegrity", err)
	}
	consumption.ConsumedAt = grant.ExpiresAt
	if _, err := consumption.Seal(); !errors.Is(err, ErrApprovalGrantIntegrity) {
		t.Fatalf("late Seal() error = %v, want ErrApprovalGrantIntegrity", err)
	}

	consumption = validApprovalGrantConsumption(grant)
	consumption, err = consumption.Seal()
	if err != nil {
		t.Fatal(err)
	}
	tamperedGrant := grant
	tamperedGrant.CeremonyHash = sha256Ref("9")
	if err := consumption.ValidateGrant(tamperedGrant); !errors.Is(err, ErrApprovalGrantIntegrity) {
		t.Fatalf("tampered grant ValidateGrant() error = %v, want ErrApprovalGrantIntegrity", err)
	}
}

func validApprovalGrantConsumption(grant ApprovalGrant) ApprovalGrantConsumption {
	return ApprovalGrantConsumption{
		SchemaVersion: ApprovalGrantConsumptionSchemaV1, ContractVersion: ApprovalGrantConsumptionContractV1,
		ApprovalID: grant.ApprovalID, GrantID: grant.GrantID, GrantHash: grant.GrantHash,
		TenantID: grant.TenantID, WorkspaceID: grant.WorkspaceID, Audience: grant.Audience,
		ConsumedBy: "spiffe://helm/data-plane-a", PackID: grant.PackID, PackVersion: grant.PackVersion,
		PackManifestHash: grant.PackManifestHash, Action: grant.Action,
		IntentHash: grant.IntentHash, EffectHash: grant.EffectHash, PlanHash: grant.PlanHash,
		PolicyVersion: grant.PolicyVersion, PolicyEpoch: grant.PolicyEpoch, PolicyHash: grant.PolicyHash,
		ServerIdentity: grant.ServerIdentity, KernelTrustRootID: grant.KernelTrustRootID, SigningKeyRef: grant.SigningKeyRef,
		GrantIssuedAt: grant.IssuedAt, GrantExpiresAt: grant.ExpiresAt, ConsumedAt: grant.IssuedAt.Add(time.Minute),
	}
}
