package install

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryStore_CRUD(t *testing.T) {
	store := NewMemoryStore()

	if _, err := store.Get("missing"); err == nil {
		t.Error("Get(missing): expected error")
	}

	state := &State{PackID: "p1", Version: "0.1.0", Status: "installed"}
	if err := store.Put(state); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := store.Get("p1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Version != "0.1.0" {
		t.Errorf("Version = %q", got.Version)
	}

	all, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("List len = %d, want 1", len(all))
	}

	if err := store.Delete("p1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get("p1"); err == nil {
		t.Error("Get after Delete: expected error")
	}
}

func TestMemoryStore_Clone_Isolation(t *testing.T) {
	store := NewMemoryStore()

	original := &State{PackID: "p1", Version: "0.1.0", Status: "installed"}
	if err := store.Put(original); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Mutating the caller-side pointer must not leak into the store.
	original.Version = "0.9.9"

	got, err := store.Get("p1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Version != "0.1.0" {
		t.Errorf("stored Version = %q, want 0.1.0 (caller mutation leaked)", got.Version)
	}

	// Mutating the returned clone must not leak back.
	got.Version = "changed"
	again, err := store.Get("p1")
	if err != nil {
		t.Fatalf("Get (again): %v", err)
	}
	if again.Version != "0.1.0" {
		t.Errorf("stored Version after clone-mutation = %q, want 0.1.0", again.Version)
	}
}

func TestMemoryStore_PutValidates(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Put(nil); !errors.Is(err, ErrInvalidState) {
		t.Errorf("Put(nil) = %v, want ErrInvalidState", err)
	}
	if err := store.Put(&State{}); !errors.Is(err, ErrInvalidState) {
		t.Errorf("Put(empty) = %v, want ErrInvalidState", err)
	}
}

func TestChannelClassification(t *testing.T) {
	if !IsKnownChannel(PackChannelCore) {
		t.Error("core: IsKnownChannel = false")
	}
	if !IsKnownChannel(PackChannelCommunity) {
		t.Error("community: IsKnownChannel = false")
	}
	if !IsKnownChannel(PackChannelTeams) {
		t.Error("teams: IsKnownChannel = false")
	}
	if !IsKnownChannel(PackChannelEnterprise) {
		t.Error("enterprise: IsKnownChannel = false")
	}
	if IsKnownChannel("") {
		t.Error("empty: IsKnownChannel = true")
	}

	if ok, reason := IsInstallableByOSS(PackChannelCore); !ok || reason != "" {
		t.Errorf("core eligibility = (%v,%q), want (true,\"\")", ok, reason)
	}
	if ok, _ := IsInstallableByOSS(PackChannelCommunity); !ok {
		t.Error("community: IsInstallableByOSS = false")
	}
	if ok, reason := IsInstallableByOSS(PackChannelTeams); ok || reason == "" {
		t.Errorf("teams eligibility = (%v,%q), want (false, non-empty)", ok, reason)
	}
	if ok, _ := IsInstallableByOSS(PackChannelEnterprise); ok {
		t.Error("enterprise: IsInstallableByOSS = true")
	}
}

func TestPlan_CoreChannel(t *testing.T) {
	runner := NewRunner(NewMemoryStore())
	manifest := sampleManifest()
	plan, err := runner.Plan(context.Background(), manifest.PackID, manifest, ActionInstall, Options{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !plan.Eligible {
		t.Errorf("core Plan.Eligible = false, reasons = %v", plan.IneligibleReasons)
	}
}

func TestPlan_CommunityChannel(t *testing.T) {
	runner := NewRunner(NewMemoryStore())
	manifest := sampleManifest()
	manifest.Channel = PackChannelCommunity
	plan, err := runner.Plan(context.Background(), manifest.PackID, manifest, ActionInstall, Options{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !plan.Eligible {
		t.Errorf("community Plan.Eligible = false, reasons = %v", plan.IneligibleReasons)
	}
}

func TestPlan_TeamsChannel(t *testing.T) {
	runner := NewRunner(NewMemoryStore())
	manifest := sampleManifest()
	manifest.Channel = PackChannelTeams
	plan, err := runner.Plan(context.Background(), manifest.PackID, manifest, ActionInstall, Options{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Eligible {
		t.Error("teams Plan.Eligible = true, want false")
	}
	if len(plan.IneligibleReasons) == 0 {
		t.Error("teams Plan.IneligibleReasons empty")
	}

	// Install path must also surface ErrIneligible for teams.
	if _, err := runner.Install(context.Background(), manifest.PackID, manifest, Options{}); !errors.Is(err, ErrIneligible) {
		t.Errorf("Install(teams) err = %v, want ErrIneligible", err)
	}
}

func TestPlan_EnterpriseChannel(t *testing.T) {
	runner := NewRunner(NewMemoryStore())
	manifest := sampleManifest()
	manifest.Channel = PackChannelEnterprise
	plan, err := runner.Plan(context.Background(), manifest.PackID, manifest, ActionInstall, Options{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Eligible {
		t.Error("enterprise Plan.Eligible = true, want false")
	}
	if len(plan.IneligibleReasons) == 0 {
		t.Error("enterprise Plan.IneligibleReasons empty")
	}
}
