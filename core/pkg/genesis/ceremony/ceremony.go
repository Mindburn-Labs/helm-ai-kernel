// Package ceremony provides the VGL (Verified Genesis Loop) state machine
// and ceremony orchestrator. This is the most important governance surface:
// no genome activates without completing all 6 phases.
//
// This package is the OSS-side home for the genesis ceremony engine. It is
// intentionally transport-free — HTTP handlers and tenant-routing belong in
// the commercial control plane or in a local binary wrapping this engine.
// OrgID is kept as a logical identifier only (no multi-tenant semantics).
package ceremony

import (
	crypto_rand "crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Phase represents a stage in the genesis ceremony.
type Phase string

const (
	// PhaseIngest is US-09: draft nodes created.
	PhaseIngest Phase = "INGEST"
	// PhaseMirror is US-10: deterministic semantic mirror.
	PhaseMirror Phase = "MIRROR"
	// PhaseWargame is US-11: blast radius simulation.
	PhaseWargame Phase = "WARGAME"
	// PhaseCeilings is US-12: P0 ceiling binding.
	PhaseCeilings Phase = "CEILINGS"
	// PhaseReview is the pre-activation review.
	PhaseReview Phase = "REVIEW"
	// PhaseActivation is US-13: hold-to-sign → ORG_GENESIS_APPROVAL.
	PhaseActivation Phase = "ACTIVATION"
)

// Status represents the overall genesis status.
type Status string

const (
	// StatusDraft indicates the ceremony has been created but no phase has advanced.
	StatusDraft Status = "DRAFT"
	// StatusInProgress indicates a phase is actively running.
	StatusInProgress Status = "IN_PROGRESS"
	// StatusPending indicates the ceremony is waiting for a governance decision.
	StatusPending Status = "PENDING_APPROVAL"
	// StatusActive indicates the genome has been activated.
	StatusActive Status = "ACTIVE"
	// StatusFailed indicates the ceremony terminated unsuccessfully.
	StatusFailed Status = "FAILED"
)

// Ceremony tracks the full genesis state machine.
type Ceremony struct {
	ID              string                `json:"id"`
	OrgID           string                `json:"org_id"`
	Status          Status                `json:"status"`
	CurrentPhase    Phase                 `json:"current_phase"`
	Phases          map[Phase]*PhaseState `json:"phases"`
	GenomeDraftHash string                `json:"genome_draft_hash"`
	CreatedAt       time.Time             `json:"created_at"`
	CompletedAt     *time.Time            `json:"completed_at,omitempty"`

	// Accumulated hashes
	CompileReceiptHash string `json:"compile_receipt_hash,omitempty"`
	MirrorTextHash     string `json:"mirror_text_hash,omitempty"`
	ImpactReportHash   string `json:"impact_report_hash,omitempty"`
	P0CeilingsHash     string `json:"p0_ceilings_hash,omitempty"`
	GenesisReceiptHash string `json:"genesis_receipt_hash,omitempty"`
}

// PhaseState tracks a single phase's lifecycle within a ceremony.
type PhaseState struct {
	Phase       Phase      `json:"phase"`
	Status      string     `json:"status"` // "pending", "in_progress", "completed", "failed"
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	ReceiptHash string     `json:"receipt_hash,omitempty"`
	SignerID    string     `json:"signer_id,omitempty"`
}

// Store is the persistence interface for genesis ceremonies.
type Store interface {
	Create(ceremony *Ceremony) error
	Get(id string) (*Ceremony, error)
	Update(ceremony *Ceremony) error
	GetByOrg(orgID string) (*Ceremony, error)
}

// Orchestrator manages genesis ceremonies on top of a Store.
type Orchestrator struct {
	store Store
}

// NewOrchestrator creates a genesis ceremony orchestrator.
func NewOrchestrator(store Store) *Orchestrator {
	return &Orchestrator{store: store}
}

// Get returns a ceremony by id.
func (o *Orchestrator) Get(id string) (*Ceremony, error) {
	return o.store.Get(id)
}

// GetByOrg returns the latest ceremony for an org.
func (o *Orchestrator) GetByOrg(orgID string) (*Ceremony, error) {
	return o.store.GetByOrg(orgID)
}

// EnsureCeremony returns the existing ceremony for an org or starts a new one.
func (o *Orchestrator) EnsureCeremony(orgID, genomeDraftHash string) (*Ceremony, error) {
	ceremony, err := o.store.GetByOrg(orgID)
	if err == nil {
		return ceremony, nil
	}
	return o.StartCeremony(orgID, genomeDraftHash)
}

// StartCeremony creates a new genesis ceremony for an org.
func (o *Orchestrator) StartCeremony(orgID, genomeDraftHash string) (*Ceremony, error) {
	ceremony := &Ceremony{
		ID:              generateID(),
		OrgID:           orgID,
		Status:          StatusDraft,
		CurrentPhase:    PhaseIngest,
		GenomeDraftHash: genomeDraftHash,
		CreatedAt:       time.Now(),
		Phases:          initPhases(),
	}

	if err := o.store.Create(ceremony); err != nil {
		return nil, fmt.Errorf("create ceremony: %w", err)
	}
	return ceremony, nil
}

// MarkPendingApproval records that the ceremony is waiting for a governance decision.
func (o *Orchestrator) MarkPendingApproval(ceremonyID string) (*Ceremony, error) {
	ceremony, err := o.store.Get(ceremonyID)
	if err != nil {
		return nil, fmt.Errorf("get ceremony: %w", err)
	}
	if ceremony.Status == StatusActive {
		return ceremony, nil
	}
	ceremony.Status = StatusPending
	if err := o.store.Update(ceremony); err != nil {
		return nil, fmt.Errorf("update ceremony: %w", err)
	}
	return ceremony, nil
}

// AdvancePhase attempts to move to the next phase. Each phase must be
// in_progress before advancing.
func (o *Orchestrator) AdvancePhase(ceremonyID string, receiptHash string, signerID string) (*Ceremony, error) {
	ceremony, err := o.store.Get(ceremonyID)
	if err != nil {
		return nil, fmt.Errorf("get ceremony: %w", err)
	}

	phase := ceremony.Phases[ceremony.CurrentPhase]
	if phase.Status != "in_progress" {
		return nil, fmt.Errorf("phase %s is not in progress (status: %s)", ceremony.CurrentPhase, phase.Status)
	}

	// Mark current phase complete.
	now := time.Now()
	phase.Status = "completed"
	phase.CompletedAt = &now
	phase.ReceiptHash = receiptHash
	phase.SignerID = signerID

	// Store phase-specific hashes.
	switch ceremony.CurrentPhase {
	case PhaseIngest:
		ceremony.CompileReceiptHash = receiptHash
	case PhaseMirror:
		ceremony.MirrorTextHash = receiptHash
	case PhaseWargame:
		ceremony.ImpactReportHash = receiptHash
	case PhaseCeilings:
		ceremony.P0CeilingsHash = receiptHash
	case PhaseActivation:
		ceremony.GenesisReceiptHash = receiptHash
		ceremony.Status = StatusActive
		ceremony.CompletedAt = &now
	}

	// Advance to next phase.
	next := nextPhase(ceremony.CurrentPhase)
	if next != "" {
		ceremony.CurrentPhase = next
		ceremony.Phases[next].Status = "in_progress"
		startNow := time.Now()
		ceremony.Phases[next].StartedAt = &startNow
		ceremony.Status = StatusInProgress
	}

	if err := o.store.Update(ceremony); err != nil {
		return nil, fmt.Errorf("update ceremony: %w", err)
	}
	return ceremony, nil
}

// initPhases builds the initial PhaseState map with PhaseIngest marked in_progress
// and the remaining phases pending.
func initPhases() map[Phase]*PhaseState {
	phases := map[Phase]*PhaseState{}
	for _, p := range []Phase{PhaseIngest, PhaseMirror, PhaseWargame, PhaseCeilings, PhaseReview, PhaseActivation} {
		status := "pending"
		if p == PhaseIngest {
			status = "in_progress"
		}
		phases[p] = &PhaseState{Phase: p, Status: status}
	}
	now := time.Now()
	phases[PhaseIngest].StartedAt = &now
	return phases
}

// nextPhase returns the Phase that follows current, or "" if current is the last.
func nextPhase(current Phase) Phase {
	order := []Phase{PhaseIngest, PhaseMirror, PhaseWargame, PhaseCeilings, PhaseReview, PhaseActivation}
	for i, p := range order {
		if p == current && i < len(order)-1 {
			return order[i+1]
		}
	}
	return ""
}

// generateID returns a randomized, prefixed ceremony identifier.
func generateID() string {
	b := make([]byte, 8)
	if _, err := crypto_rand.Read(b); err != nil {
		return fmt.Sprintf("gen-%d", time.Now().UnixNano())
	}
	return "gen-" + hex.EncodeToString(b)
}
