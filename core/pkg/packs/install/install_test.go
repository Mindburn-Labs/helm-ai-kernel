package install

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func fixedNow() time.Time {
	return time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
}

func communityManifest() contracts.PackManifestV2 {
	return contracts.PackManifestV2{
		PackID:  "demo-pack",
		Name:    "Demo",
		Version: "0.1.0",
		Channel: contracts.PackChannelCommunity,
	}
}

// TestInstall_Fresh confirms a first install produces a receipt and
// persisted state with Status=installed.
func TestInstall_Fresh(t *testing.T) {
	store := NewMemoryStore()
	r := NewRunner(store)
	now := fixedNow()

	result, err := r.Install(context.Background(), communityManifest(), "sha256:abc", InstallOptions{
		InstalledBy: "operator-local",
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if result.Action != ActionInstall {
		t.Fatalf("Action: %q", result.Action)
	}
	if result.State == nil || result.State.Status != "installed" {
		t.Fatalf("State: %+v", result.State)
	}
	if result.State.InstallCount != 1 {
		t.Fatalf("InstallCount: %d", result.State.InstallCount)
	}
	if result.Receipt == nil || result.Receipt.Action != ActionInstall {
		t.Fatalf("Receipt: %+v", result.Receipt)
	}
	if result.Receipt.PrevReceiptID != "" {
		t.Fatalf("first receipt must have empty PrevReceiptID, got %q", result.Receipt.PrevReceiptID)
	}
	if result.InstalledPack == nil || result.InstalledPack.Status != "installed" {
		t.Fatalf("InstalledPack: %+v", result.InstalledPack)
	}

	persisted, err := store.Get("demo-pack")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if persisted.ReceiptID != result.Receipt.ReceiptID {
		t.Fatalf("persisted ReceiptID mismatch")
	}
}

// TestInstall_Upgrade confirms an upgrade bumps version, increments
// InstallCount, and chains the receipt to the previous one.
func TestInstall_Upgrade(t *testing.T) {
	store := NewMemoryStore()
	r := NewRunner(store)
	now := fixedNow()

	m1 := communityManifest()
	first, err := r.Install(context.Background(), m1, "sha256:abc", InstallOptions{
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("first Install: %v", err)
	}

	m2 := communityManifest()
	m2.Version = "0.2.0"
	later := now.Add(time.Hour)
	second, err := r.Install(context.Background(), m2, "sha256:def", InstallOptions{
		Action: ActionUpgrade,
		Now:    func() time.Time { return later },
	})
	if err != nil {
		t.Fatalf("upgrade Install: %v", err)
	}
	if second.Action != ActionUpgrade {
		t.Fatalf("Action: %q", second.Action)
	}
	if second.State.Version != "0.2.0" {
		t.Fatalf("Version: %q", second.State.Version)
	}
	if second.State.InstallCount != 2 {
		t.Fatalf("InstallCount after upgrade: %d", second.State.InstallCount)
	}
	if second.Receipt.PrevReceiptID != first.Receipt.ReceiptID {
		t.Fatalf("chain broken: Prev=%q, want %q", second.Receipt.PrevReceiptID, first.Receipt.ReceiptID)
	}
}

// TestInstall_Uninstall marks state uninstalled and emits an uninstall
// receipt.
func TestInstall_Uninstall(t *testing.T) {
	store := NewMemoryStore()
	r := NewRunner(store)
	now := fixedNow()

	if _, err := r.Install(context.Background(), communityManifest(), "sha256:abc", InstallOptions{Now: func() time.Time { return now }}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	result, err := r.Uninstall(context.Background(), communityManifest(), "sha256:abc", InstallOptions{Now: func() time.Time { return now.Add(time.Hour) }})
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if result.State.Status != "uninstalled" {
		t.Fatalf("Status: %q", result.State.Status)
	}
	if result.State.InstalledAt != nil {
		t.Fatalf("InstalledAt should be nil after uninstall, got %v", result.State.InstalledAt)
	}
	if result.Receipt.Action != ActionUninstall {
		t.Fatalf("Receipt.Action: %q", result.Receipt.Action)
	}
}

// TestInstall_Rollback returns state to rolled_back and chains the
// receipt.
func TestInstall_Rollback(t *testing.T) {
	store := NewMemoryStore()
	r := NewRunner(store)
	now := fixedNow()

	if _, err := r.Install(context.Background(), communityManifest(), "sha256:abc", InstallOptions{Now: func() time.Time { return now }}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	result, err := r.Rollback(context.Background(), communityManifest(), "sha256:abc", InstallOptions{Now: func() time.Time { return now.Add(time.Hour) }})
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if result.State.Status != "rolled_back" {
		t.Fatalf("Status: %q", result.State.Status)
	}
	if result.Receipt.Action != ActionRollback {
		t.Fatalf("Receipt.Action: %q", result.Receipt.Action)
	}
}

// TestInstall_DryRun confirms DryRun produces a plan without mutating
// state or emitting a receipt.
func TestInstall_DryRun(t *testing.T) {
	store := NewMemoryStore()
	r := NewRunner(store)

	result, err := r.Install(context.Background(), communityManifest(), "sha256:abc", InstallOptions{
		DryRun: true,
		Now:    func() time.Time { return fixedNow() },
	})
	if err != nil {
		t.Fatalf("DryRun Install: %v", err)
	}
	if result.Receipt != nil {
		t.Fatalf("DryRun must not emit a receipt, got %+v", result.Receipt)
	}
	if !result.Plan.DryRun {
		t.Fatalf("Plan.DryRun: want true")
	}
	if _, err := store.Get("demo-pack"); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("DryRun must not persist state; got %v", err)
	}
}

// TestInstall_MissingSecret blocks install and reports the secret in
// Plan.MissingSecrets.
func TestInstall_MissingSecret(t *testing.T) {
	store := NewMemoryStore()
	r := NewRunner(store)

	manifest := communityManifest()
	manifest.Secrets = []contracts.PackSecret{{Name: "API_KEY", Required: true}}

	result, err := r.Install(context.Background(), manifest, "sha256:abc", InstallOptions{
		Now: func() time.Time { return fixedNow() },
	})
	if !errors.Is(err, ErrIneligible) {
		t.Fatalf("want ErrIneligible, got %v", err)
	}
	if result.Plan.Eligible {
		t.Fatalf("Plan.Eligible: want false")
	}
	found := false
	for _, s := range result.Plan.MissingSecrets {
		if s == "API_KEY" {
			found = true
		}
	}
	if !found {
		t.Fatalf("MissingSecrets did not report API_KEY: %v", result.Plan.MissingSecrets)
	}
}

// TestPlan_CoreChannel installs under the core channel (installable by
// OSS; no commercial gating needed).
func TestPlan_CoreChannel(t *testing.T) {
	store := NewMemoryStore()
	r := NewRunner(store)

	manifest := communityManifest()
	manifest.Channel = contracts.PackChannelCore
	manifest.PackID = "core-pack"

	plan, err := r.Plan(context.Background(), manifest, "sha256:abc", InstallOptions{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !plan.Eligible {
		t.Fatalf("core channel must be eligible; reasons=%v", plan.IneligibleReasons)
	}
	if len(plan.IneligibleReasons) != 0 {
		t.Fatalf("IneligibleReasons should be empty: %v", plan.IneligibleReasons)
	}
}

// TestPlan_CommunityChannel installs under the community channel.
func TestPlan_CommunityChannel(t *testing.T) {
	store := NewMemoryStore()
	r := NewRunner(store)

	plan, err := r.Plan(context.Background(), communityManifest(), "sha256:abc", InstallOptions{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !plan.Eligible {
		t.Fatalf("community channel must be eligible; reasons=%v", plan.IneligibleReasons)
	}
}

// TestPlan_TeamsChannel confirms OSS does NOT install teams packs;
// Plan.Eligible is false and IneligibleReasons carries a
// commercial-entitlement reason.
func TestPlan_TeamsChannel(t *testing.T) {
	store := NewMemoryStore()
	r := NewRunner(store)

	manifest := communityManifest()
	manifest.Channel = contracts.PackChannelTeams
	manifest.PackID = "teams-pack"

	plan, err := r.Plan(context.Background(), manifest, "sha256:abc", InstallOptions{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Eligible {
		t.Fatalf("teams channel must be ineligible in OSS")
	}
	if len(plan.IneligibleReasons) == 0 {
		t.Fatalf("IneligibleReasons must explain commercial entitlement")
	}

	// An actual Install must also return ErrIneligible.
	_, err = r.Install(context.Background(), manifest, "sha256:abc", InstallOptions{Now: func() time.Time { return fixedNow() }})
	if !errors.Is(err, ErrIneligible) {
		t.Fatalf("Install teams: want ErrIneligible, got %v", err)
	}
}

// TestPlan_EnterpriseChannel is symmetric to Teams — also not installable.
func TestPlan_EnterpriseChannel(t *testing.T) {
	store := NewMemoryStore()
	r := NewRunner(store)

	manifest := communityManifest()
	manifest.Channel = contracts.PackChannelEnterprise
	manifest.PackID = "ent-pack"

	plan, err := r.Plan(context.Background(), manifest, "sha256:abc", InstallOptions{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Eligible {
		t.Fatalf("enterprise channel must be ineligible in OSS")
	}
}
