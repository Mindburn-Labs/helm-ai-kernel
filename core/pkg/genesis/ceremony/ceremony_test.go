package ceremony

import (
	"strings"
	"testing"
)

// TestCeremony_StartAndGet verifies a new ceremony can be created and
// retrieved by both ID and OrgID, with the expected initial state.
func TestCeremony_StartAndGet(t *testing.T) {
	orch := NewOrchestrator(NewMemoryStore())

	c, err := orch.StartCeremony("acme-local", "sha256:draft-001")
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}

	if c.ID == "" || !strings.HasPrefix(c.ID, "gen-") {
		t.Fatalf("unexpected ID: %q", c.ID)
	}
	if c.OrgID != "acme-local" {
		t.Fatalf("OrgID: want acme-local, got %q", c.OrgID)
	}
	if c.Status != StatusDraft {
		t.Fatalf("Status: want DRAFT, got %q", c.Status)
	}
	if c.CurrentPhase != PhaseIngest {
		t.Fatalf("CurrentPhase: want INGEST, got %q", c.CurrentPhase)
	}
	if c.GenomeDraftHash != "sha256:draft-001" {
		t.Fatalf("GenomeDraftHash: got %q", c.GenomeDraftHash)
	}
	if c.CreatedAt.IsZero() {
		t.Fatalf("CreatedAt must be set")
	}
	if len(c.Phases) != 6 {
		t.Fatalf("Phases: want 6 entries, got %d", len(c.Phases))
	}
	if c.Phases[PhaseIngest].Status != "in_progress" {
		t.Fatalf("INGEST phase should start in_progress, got %q", c.Phases[PhaseIngest].Status)
	}
	if c.Phases[PhaseIngest].StartedAt == nil {
		t.Fatalf("INGEST StartedAt must be set")
	}
	for _, p := range []Phase{PhaseMirror, PhaseWargame, PhaseCeilings, PhaseReview, PhaseActivation} {
		if c.Phases[p].Status != "pending" {
			t.Fatalf("phase %s should be pending, got %q", p, c.Phases[p].Status)
		}
	}

	got, err := orch.Get(c.ID)
	if err != nil {
		t.Fatalf("Get by id: %v", err)
	}
	if got.ID != c.ID {
		t.Fatalf("round-trip id mismatch: got %q", got.ID)
	}

	gotByOrg, err := orch.GetByOrg("acme-local")
	if err != nil {
		t.Fatalf("GetByOrg: %v", err)
	}
	if gotByOrg.ID != c.ID {
		t.Fatalf("GetByOrg id mismatch: got %q", gotByOrg.ID)
	}
}

// TestCeremony_Phases walks a ceremony through all six phases via
// AdvancePhase and verifies the final ACTIVE status and GenesisReceiptHash.
func TestCeremony_Phases(t *testing.T) {
	orch := NewOrchestrator(NewMemoryStore())
	c, err := orch.StartCeremony("acme-local", "sha256:draft-002")
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}

	order := []Phase{PhaseIngest, PhaseMirror, PhaseWargame, PhaseCeilings, PhaseReview, PhaseActivation}
	for i, want := range order {
		if c.CurrentPhase != want {
			t.Fatalf("step %d: CurrentPhase want %q got %q", i, want, c.CurrentPhase)
		}
		receipt := "sha256:receipt-" + string(want)
		signer := "operator-local"
		c, err = orch.AdvancePhase(c.ID, receipt, signer)
		if err != nil {
			t.Fatalf("AdvancePhase at %s: %v", want, err)
		}
	}

	if c.Status != StatusActive {
		t.Fatalf("Status after all phases: want ACTIVE, got %q", c.Status)
	}
	if c.CompletedAt == nil {
		t.Fatalf("CompletedAt must be set after ACTIVATION")
	}
	if c.GenesisReceiptHash != "sha256:receipt-ACTIVATION" {
		t.Fatalf("GenesisReceiptHash: got %q", c.GenesisReceiptHash)
	}
	// After ACTIVATION, nextPhase returns "" so CurrentPhase stays at ACTIVATION.
	if c.CurrentPhase != PhaseActivation {
		t.Fatalf("CurrentPhase after ACTIVATION: want ACTIVATION, got %q", c.CurrentPhase)
	}
}

// TestCeremony_HashAccumulation verifies each phase writes its receipt
// into the correct accumulated-hash field on the Ceremony.
func TestCeremony_HashAccumulation(t *testing.T) {
	orch := NewOrchestrator(NewMemoryStore())
	c, err := orch.StartCeremony("acme-local", "sha256:draft-003")
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}

	// INGEST → CompileReceiptHash
	c, err = orch.AdvancePhase(c.ID, "sha256:ingest", "operator-local")
	if err != nil {
		t.Fatalf("advance INGEST: %v", err)
	}
	if c.CompileReceiptHash != "sha256:ingest" {
		t.Fatalf("CompileReceiptHash: got %q", c.CompileReceiptHash)
	}

	// MIRROR → MirrorTextHash
	c, err = orch.AdvancePhase(c.ID, "sha256:mirror", "operator-local")
	if err != nil {
		t.Fatalf("advance MIRROR: %v", err)
	}
	if c.MirrorTextHash != "sha256:mirror" {
		t.Fatalf("MirrorTextHash: got %q", c.MirrorTextHash)
	}

	// WARGAME → ImpactReportHash
	c, err = orch.AdvancePhase(c.ID, "sha256:wargame", "operator-local")
	if err != nil {
		t.Fatalf("advance WARGAME: %v", err)
	}
	if c.ImpactReportHash != "sha256:wargame" {
		t.Fatalf("ImpactReportHash: got %q", c.ImpactReportHash)
	}

	// CEILINGS → P0CeilingsHash
	c, err = orch.AdvancePhase(c.ID, "sha256:ceilings", "operator-local")
	if err != nil {
		t.Fatalf("advance CEILINGS: %v", err)
	}
	if c.P0CeilingsHash != "sha256:ceilings" {
		t.Fatalf("P0CeilingsHash: got %q", c.P0CeilingsHash)
	}

	// Per-phase ReceiptHash + SignerID must be persisted on each PhaseState.
	if c.Phases[PhaseCeilings].ReceiptHash != "sha256:ceilings" {
		t.Fatalf("PhaseCeilings.ReceiptHash: got %q", c.Phases[PhaseCeilings].ReceiptHash)
	}
	if c.Phases[PhaseCeilings].SignerID != "operator-local" {
		t.Fatalf("PhaseCeilings.SignerID: got %q", c.Phases[PhaseCeilings].SignerID)
	}
	if c.Phases[PhaseCeilings].CompletedAt == nil {
		t.Fatalf("PhaseCeilings.CompletedAt must be set")
	}
}

// TestCeremony_AdvancePhase_WrongStatus verifies AdvancePhase fails when
// the current phase is not in_progress.
func TestCeremony_AdvancePhase_WrongStatus(t *testing.T) {
	orch := NewOrchestrator(NewMemoryStore())
	c, err := orch.StartCeremony("acme-local", "sha256:draft-004")
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}

	// Force INGEST out of in_progress by tampering with the stored copy
	// via a direct store Update. We read, mutate, write back.
	store := orch.store
	stored, err := store.Get(c.ID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	stored.Phases[PhaseIngest].Status = "completed"
	if err := store.Update(stored); err != nil {
		t.Fatalf("store.Update: %v", err)
	}

	if _, err := orch.AdvancePhase(c.ID, "sha256:ingest", "operator-local"); err == nil {
		t.Fatalf("expected error when phase not in_progress")
	}
}

// TestCeremony_EnsureCeremony_ReturnsExisting verifies EnsureCeremony is
// idempotent: a second call for the same OrgID returns the existing
// ceremony without creating a new one.
func TestCeremony_EnsureCeremony_ReturnsExisting(t *testing.T) {
	orch := NewOrchestrator(NewMemoryStore())

	first, err := orch.EnsureCeremony("acme-local", "sha256:draft-a")
	if err != nil {
		t.Fatalf("first EnsureCeremony: %v", err)
	}
	second, err := orch.EnsureCeremony("acme-local", "sha256:draft-b")
	if err != nil {
		t.Fatalf("second EnsureCeremony: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("EnsureCeremony should return existing ceremony; got new ID %q (first was %q)", second.ID, first.ID)
	}
	// Draft hash must be the original — EnsureCeremony must not clobber it.
	if second.GenomeDraftHash != "sha256:draft-a" {
		t.Fatalf("EnsureCeremony clobbered GenomeDraftHash: got %q", second.GenomeDraftHash)
	}
}

// TestCeremony_MarkPendingApproval verifies the status transitions to
// PENDING_APPROVAL, and that a ceremony already ACTIVE is left alone.
func TestCeremony_MarkPendingApproval(t *testing.T) {
	orch := NewOrchestrator(NewMemoryStore())
	c, err := orch.StartCeremony("acme-local", "sha256:draft-005")
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}

	pending, err := orch.MarkPendingApproval(c.ID)
	if err != nil {
		t.Fatalf("MarkPendingApproval: %v", err)
	}
	if pending.Status != StatusPending {
		t.Fatalf("Status: want PENDING_APPROVAL, got %q", pending.Status)
	}

	// Force ACTIVE via the store, then verify MarkPendingApproval is a no-op.
	store := orch.store
	stored, err := store.Get(c.ID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	stored.Status = StatusActive
	if err := store.Update(stored); err != nil {
		t.Fatalf("store.Update: %v", err)
	}

	after, err := orch.MarkPendingApproval(c.ID)
	if err != nil {
		t.Fatalf("MarkPendingApproval (active): %v", err)
	}
	if after.Status != StatusActive {
		t.Fatalf("MarkPendingApproval must not demote ACTIVE; got %q", after.Status)
	}
}

// TestMemoryStore_CRUD exercises the Store interface directly without
// the Orchestrator wrapper.
func TestMemoryStore_CRUD(t *testing.T) {
	store := NewMemoryStore()

	c := &Ceremony{
		ID:           "gen-test-001",
		OrgID:        "acme-local",
		Status:       StatusDraft,
		CurrentPhase: PhaseIngest,
		Phases:       initPhases(),
	}

	// Create
	if err := store.Create(c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Get by ID
	got, err := store.Get("gen-test-001")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != c.ID {
		t.Fatalf("Get returned wrong ceremony: %q", got.ID)
	}

	// Get by OrgID
	gotByOrg, err := store.GetByOrg("acme-local")
	if err != nil {
		t.Fatalf("GetByOrg: %v", err)
	}
	if gotByOrg.ID != c.ID {
		t.Fatalf("GetByOrg returned wrong ceremony: %q", gotByOrg.ID)
	}

	// Update
	got.Status = StatusInProgress
	if err := store.Update(got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	refetched, err := store.Get(c.ID)
	if err != nil {
		t.Fatalf("Get after Update: %v", err)
	}
	if refetched.Status != StatusInProgress {
		t.Fatalf("Update did not persist Status: got %q", refetched.Status)
	}

	// Get missing
	if _, err := store.Get("gen-nonexistent"); err == nil {
		t.Fatalf("Get missing: want error")
	}
	if _, err := store.GetByOrg("no-such-org"); err == nil {
		t.Fatalf("GetByOrg missing: want error")
	}

	// Update missing
	missing := &Ceremony{ID: "gen-nonexistent", OrgID: "acme-local"}
	if err := store.Update(missing); err == nil {
		t.Fatalf("Update missing: want error")
	}
}

// TestMemoryStore_Clone_Isolation verifies that mutating a returned
// ceremony does not affect the stored copy — the store hands out clones.
func TestMemoryStore_Clone_Isolation(t *testing.T) {
	store := NewMemoryStore()
	c := &Ceremony{
		ID:           "gen-test-002",
		OrgID:        "acme-local",
		Status:       StatusDraft,
		CurrentPhase: PhaseIngest,
		Phases:       initPhases(),
	}
	if err := store.Create(c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get(c.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got.Status = StatusFailed
	got.Phases[PhaseIngest].Status = "failed"

	refetched, err := store.Get(c.ID)
	if err != nil {
		t.Fatalf("Get second: %v", err)
	}
	if refetched.Status == StatusFailed {
		t.Fatalf("Store must hand out clones; external mutation leaked Status")
	}
	if refetched.Phases[PhaseIngest].Status == "failed" {
		t.Fatalf("Store must hand out clones; external mutation leaked Phases[INGEST].Status")
	}
}

// TestCeremony_GenerateIDUnique verifies generateID produces distinct
// values across repeated calls (probabilistic; 8 random bytes).
func TestCeremony_GenerateIDUnique(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		id := generateID()
		if !strings.HasPrefix(id, "gen-") {
			t.Fatalf("generateID missing gen- prefix: %q", id)
		}
		if seen[id] {
			t.Fatalf("generateID collision: %q", id)
		}
		seen[id] = true
	}
}
