package install

import (
	"context"
	"errors"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func sampleManifest() contracts.PackManifestV2 {
	return contracts.PackManifestV2{
		PackID:         "example.compliance/hipaa",
		Name:           "HIPAA Guardrails",
		Version:        "0.1.0",
		Channel:        contracts.PackChannelCore,
		MinimumEdition: "oss",
	}
}

func TestInstall_Fresh(t *testing.T) {
	runner := NewRunner(NewMemoryStore())
	result, err := runner.Install(context.Background(), "example.compliance/hipaa", sampleManifest(), Options{})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if result.Action != ActionInstall {
		t.Errorf("Action = %q, want install", result.Action)
	}
	if !result.Plan.Eligible {
		t.Errorf("Plan.Eligible = false, want true")
	}
	if result.InstalledPack == nil || result.InstalledPack.Status != "installed" {
		t.Errorf("InstalledPack = %+v, want status installed", result.InstalledPack)
	}
	if result.Receipt == nil || result.Receipt.Hash == "" {
		t.Errorf("Receipt missing or unhashed")
	}
	if result.State.InstallCount != 1 {
		t.Errorf("InstallCount = %d, want 1", result.State.InstallCount)
	}
}

func TestInstall_Upgrade(t *testing.T) {
	runner := NewRunner(NewMemoryStore())
	manifest := sampleManifest()

	if _, err := runner.Install(context.Background(), manifest.PackID, manifest, Options{}); err != nil {
		t.Fatalf("first Install: %v", err)
	}

	manifest.Version = "0.2.0"
	result, err := runner.Install(context.Background(), manifest.PackID, manifest, Options{})
	if err != nil {
		t.Fatalf("upgrade Install: %v", err)
	}
	if result.Action != ActionUpgrade {
		t.Errorf("Action = %q, want upgrade", result.Action)
	}
	if !result.Plan.RequiresUpgrade {
		t.Errorf("Plan.RequiresUpgrade = false, want true")
	}
	if result.State.Version != "0.2.0" {
		t.Errorf("State.Version = %q, want 0.2.0", result.State.Version)
	}
	if result.State.InstallCount != 2 {
		t.Errorf("InstallCount = %d, want 2", result.State.InstallCount)
	}
}

func TestInstall_Rollback(t *testing.T) {
	runner := NewRunner(NewMemoryStore())
	manifest := sampleManifest()

	installResult, err := runner.Install(context.Background(), manifest.PackID, manifest, Options{})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	rollbackReceipt, err := runner.Rollback(context.Background(), manifest.PackID)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rollbackReceipt.Action != ActionRollback {
		t.Errorf("Receipt.Action = %q, want rollback", rollbackReceipt.Action)
	}
	if rollbackReceipt.PrevReceiptHash != installResult.Receipt.Hash {
		t.Errorf("PrevReceiptHash chain broken: got %q, want %q", rollbackReceipt.PrevReceiptHash, installResult.Receipt.Hash)
	}

	// Rollback against missing state should error cleanly.
	runner2 := NewRunner(NewMemoryStore())
	if _, err := runner2.Rollback(context.Background(), "missing"); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("Rollback(missing) err = %v, want ErrStateNotFound", err)
	}
}

func TestInstall_DryRun(t *testing.T) {
	store := NewMemoryStore()
	runner := NewRunner(store)
	result, err := runner.Install(context.Background(), "example.compliance/hipaa", sampleManifest(), Options{DryRun: true})
	if err != nil {
		t.Fatalf("Install dry-run: %v", err)
	}
	if !result.Plan.DryRun {
		t.Errorf("Plan.DryRun = false, want true")
	}
	if result.State != nil {
		t.Errorf("dry-run produced State = %+v, want nil", result.State)
	}
	if _, err := store.Get("example.compliance/hipaa"); err == nil {
		t.Error("dry-run leaked state into store")
	}
}

func TestInstall_Uninstall(t *testing.T) {
	runner := NewRunner(NewMemoryStore())
	manifest := sampleManifest()
	installed, err := runner.Install(context.Background(), manifest.PackID, manifest, Options{})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	receipt, err := runner.Uninstall(context.Background(), manifest.PackID)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if receipt.Action != ActionUninstall {
		t.Errorf("Receipt.Action = %q, want uninstall", receipt.Action)
	}
	if receipt.PrevReceiptHash != installed.Receipt.Hash {
		t.Errorf("PrevReceiptHash chain broken")
	}
}

func TestInstall_MissingSecret(t *testing.T) {
	runner := NewRunner(NewMemoryStore())
	manifest := sampleManifest()
	manifest.Secrets = []contracts.PackSecret{
		{Name: "EXAMPLE_TOKEN", Description: "redacted", Required: true},
	}

	result, err := runner.Install(context.Background(), manifest.PackID, manifest, Options{})
	if !errors.Is(err, ErrIneligible) {
		t.Fatalf("Install err = %v, want ErrIneligible", err)
	}
	if result.Plan.Eligible {
		t.Error("Plan.Eligible = true, want false")
	}
	if len(result.Plan.MissingSecrets) != 1 || result.Plan.MissingSecrets[0] != "EXAMPLE_TOKEN" {
		t.Errorf("MissingSecrets = %v, want [EXAMPLE_TOKEN]", result.Plan.MissingSecrets)
	}

	// Supplying the secret makes the plan eligible.
	ok, err := runner.Install(context.Background(), manifest.PackID, manifest, Options{Secrets: map[string]string{"EXAMPLE_TOKEN": "value"}})
	if err != nil {
		t.Fatalf("Install with secret: %v", err)
	}
	if !ok.Plan.Eligible {
		t.Error("Plan.Eligible = false after providing secret")
	}
}
