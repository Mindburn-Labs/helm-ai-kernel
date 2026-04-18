package ceremony

import (
	"strings"
	"testing"
)

func TestCeremony_StartAndGet(t *testing.T) {
	store := NewMemoryStore()
	orchestrator := NewOrchestrator(store)

	ceremony, err := orchestrator.StartCeremony("org-1", "hash-123")
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}
	if ceremony.ID == "" {
		t.Fatal("StartCeremony returned empty ID")
	}
	if ceremony.OrgID != "org-1" {
		t.Errorf("OrgID = %q, want org-1", ceremony.OrgID)
	}
	if ceremony.Status != StatusDraft {
		t.Errorf("Status = %q, want DRAFT", ceremony.Status)
	}
	if ceremony.CurrentPhase != PhaseIngest {
		t.Errorf("CurrentPhase = %q, want INGEST", ceremony.CurrentPhase)
	}
	if ceremony.GenomeDraftHash != "hash-123" {
		t.Errorf("GenomeDraftHash = %q, want hash-123", ceremony.GenomeDraftHash)
	}

	roundtrip, err := orchestrator.Get(ceremony.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if roundtrip.ID != ceremony.ID {
		t.Errorf("roundtrip ID = %q, want %q", roundtrip.ID, ceremony.ID)
	}
}

func TestCeremony_Phases(t *testing.T) {
	store := NewMemoryStore()
	orchestrator := NewOrchestrator(store)

	ceremony, err := orchestrator.StartCeremony("org-2", "hash")
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}

	for _, phase := range []Phase{PhaseIngest, PhaseMirror, PhaseWargame, PhaseCeilings, PhaseReview, PhaseActivation} {
		if _, ok := ceremony.Phases[phase]; !ok {
			t.Errorf("phase %s missing from Phases map", phase)
		}
	}

	if ceremony.Phases[PhaseIngest].Status != "in_progress" {
		t.Errorf("PhaseIngest.Status = %q, want in_progress", ceremony.Phases[PhaseIngest].Status)
	}
	if ceremony.Phases[PhaseIngest].StartedAt == nil {
		t.Error("PhaseIngest.StartedAt is nil")
	}

	for _, phase := range []Phase{PhaseMirror, PhaseWargame, PhaseCeilings, PhaseReview, PhaseActivation} {
		if ceremony.Phases[phase].Status != "pending" {
			t.Errorf("phase %s status = %q, want pending", phase, ceremony.Phases[phase].Status)
		}
	}
}

func TestCeremony_HashAccumulation(t *testing.T) {
	store := NewMemoryStore()
	orchestrator := NewOrchestrator(store)

	ceremony, err := orchestrator.StartCeremony("org-3", "draft-hash")
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}

	phaseHashes := []struct {
		phase       Phase
		receiptHash string
		field       func(*Ceremony) string
	}{
		{PhaseIngest, "ingest-hash", func(c *Ceremony) string { return c.CompileReceiptHash }},
		{PhaseMirror, "mirror-hash", func(c *Ceremony) string { return c.MirrorTextHash }},
		{PhaseWargame, "wargame-hash", func(c *Ceremony) string { return c.ImpactReportHash }},
		{PhaseCeilings, "ceilings-hash", func(c *Ceremony) string { return c.P0CeilingsHash }},
		{PhaseReview, "review-hash", nil},
		{PhaseActivation, "activation-hash", func(c *Ceremony) string { return c.GenesisReceiptHash }},
	}

	for _, step := range phaseHashes {
		if ceremony.CurrentPhase != step.phase {
			t.Fatalf("at step %s: CurrentPhase = %q, want %q", step.phase, ceremony.CurrentPhase, step.phase)
		}
		advanced, err := orchestrator.AdvancePhase(ceremony.ID, step.receiptHash, "signer")
		if err != nil {
			t.Fatalf("AdvancePhase(%s): %v", step.phase, err)
		}
		if step.field != nil && step.field(advanced) != step.receiptHash {
			t.Errorf("phase %s: accumulator = %q, want %q", step.phase, step.field(advanced), step.receiptHash)
		}
		ceremony = advanced
	}

	if ceremony.Status != StatusActive {
		t.Errorf("final Status = %q, want ACTIVE", ceremony.Status)
	}
	if ceremony.CompletedAt == nil {
		t.Error("CompletedAt is nil after activation")
	}
}

func TestCeremony_AdvancePhase_WrongStatus(t *testing.T) {
	store := NewMemoryStore()
	orchestrator := NewOrchestrator(store)

	ceremony, err := orchestrator.StartCeremony("org-4", "hash")
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}

	// Force the current phase into an unexpected status.
	ceremony.Phases[ceremony.CurrentPhase].Status = "pending"
	if err := store.Update(ceremony); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if _, err := orchestrator.AdvancePhase(ceremony.ID, "r", "s"); err == nil {
		t.Error("expected error when advancing a non-in_progress phase")
	} else if !strings.Contains(err.Error(), "not in progress") {
		t.Errorf("error = %v, want substring 'not in progress'", err)
	}
}

func TestCeremony_EnsureCeremony_ReturnsExisting(t *testing.T) {
	store := NewMemoryStore()
	orchestrator := NewOrchestrator(store)

	first, err := orchestrator.StartCeremony("org-5", "hash-a")
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}

	second, err := orchestrator.EnsureCeremony("org-5", "hash-b")
	if err != nil {
		t.Fatalf("EnsureCeremony: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("EnsureCeremony returned new id %q, want existing %q", second.ID, first.ID)
	}
	if second.GenomeDraftHash != "hash-a" {
		t.Errorf("GenomeDraftHash = %q, want original hash-a", second.GenomeDraftHash)
	}

	fresh, err := orchestrator.EnsureCeremony("org-6", "hash-c")
	if err != nil {
		t.Fatalf("EnsureCeremony (new): %v", err)
	}
	if fresh.OrgID != "org-6" {
		t.Errorf("fresh OrgID = %q, want org-6", fresh.OrgID)
	}
}

func TestCeremony_MarkPendingApproval(t *testing.T) {
	store := NewMemoryStore()
	orchestrator := NewOrchestrator(store)

	ceremony, err := orchestrator.StartCeremony("org-7", "hash")
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}

	pending, err := orchestrator.MarkPendingApproval(ceremony.ID)
	if err != nil {
		t.Fatalf("MarkPendingApproval: %v", err)
	}
	if pending.Status != StatusPending {
		t.Errorf("Status = %q, want PENDING_APPROVAL", pending.Status)
	}

	// Once active, marking pending must be a no-op.
	pending.Status = StatusActive
	if err := store.Update(pending); err != nil {
		t.Fatalf("Update: %v", err)
	}
	afterActive, err := orchestrator.MarkPendingApproval(ceremony.ID)
	if err != nil {
		t.Fatalf("MarkPendingApproval post-active: %v", err)
	}
	if afterActive.Status != StatusActive {
		t.Errorf("Status = %q, want ACTIVE unchanged", afterActive.Status)
	}
}

func TestMemoryStore_CRUD(t *testing.T) {
	store := NewMemoryStore()

	if _, err := store.Get("missing"); err == nil {
		t.Error("Get(missing): expected error")
	}
	if _, err := store.GetByOrg("missing"); err == nil {
		t.Error("GetByOrg(missing): expected error")
	}

	ceremony := &Ceremony{ID: "c-1", OrgID: "o-1", Phases: initPhases()}
	if err := store.Create(ceremony); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get("c-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.OrgID != "o-1" {
		t.Errorf("OrgID = %q, want o-1", got.OrgID)
	}

	got.OrgID = "o-1-modified"
	if err := store.Update(got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := store.Update(&Ceremony{ID: "nonexistent"}); err == nil {
		t.Error("Update(nonexistent): expected error")
	}

	byOrg, err := store.GetByOrg("o-1-modified")
	if err != nil {
		t.Fatalf("GetByOrg: %v", err)
	}
	if byOrg.ID != "c-1" {
		t.Errorf("GetByOrg ID = %q, want c-1", byOrg.ID)
	}
}

func TestMemoryStore_Clone_Isolation(t *testing.T) {
	store := NewMemoryStore()

	original := &Ceremony{
		ID:     "iso-1",
		OrgID:  "org",
		Status: StatusDraft,
		Phases: initPhases(),
	}
	if err := store.Create(original); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Mutating the original after Create must not leak into the store.
	original.Status = StatusFailed
	original.Phases[PhaseIngest].Status = "failed"

	got, err := store.Get("iso-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusDraft {
		t.Errorf("stored Status = %q, want DRAFT (caller mutation leaked)", got.Status)
	}
	if got.Phases[PhaseIngest].Status != "in_progress" {
		t.Errorf("stored PhaseIngest.Status = %q, want in_progress (phase map mutation leaked)", got.Phases[PhaseIngest].Status)
	}

	// Mutating the returned clone must not leak back either.
	got.Status = StatusFailed
	got.Phases[PhaseMirror].Status = "failed"

	again, err := store.Get("iso-1")
	if err != nil {
		t.Fatalf("Get (again): %v", err)
	}
	if again.Status != StatusDraft {
		t.Errorf("stored Status after clone-mutation = %q, want DRAFT", again.Status)
	}
	if again.Phases[PhaseMirror].Status != "pending" {
		t.Errorf("stored PhaseMirror.Status = %q, want pending", again.Phases[PhaseMirror].Status)
	}
}

func TestCeremony_GenerateIDUnique(t *testing.T) {
	const n = 200
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := generateID()
		if id == "" {
			t.Fatalf("generateID() returned empty string on iteration %d", i)
		}
		if !strings.HasPrefix(id, "gen-") {
			t.Errorf("generateID() = %q, want gen- prefix", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("generateID collision at iteration %d: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}
