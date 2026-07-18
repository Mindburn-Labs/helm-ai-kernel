package approvalceremony

import (
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type EffectReservationState string

const (
	EffectReservationStateAdmitted   EffectReservationState = "ADMITTED"
	EffectReservationStateStarted    EffectReservationState = "STARTED"
	EffectReservationStateNotStarted EffectReservationState = "NOT_STARTED"
	EffectReservationStateUncertain  EffectReservationState = "UNCERTAIN"
)

var (
	ErrEffectReservationConflict       = errors.New("approval effect reservation conflict")
	ErrEffectReservationTerminal       = errors.New("approval effect reservation is terminal")
	ErrEffectReservationAlreadyStarted = errors.New("approval effect reservation start already claimed")
)

// EffectReservationEvent is one append-only transition for a connector effect.
// Sequence 1 is the transactionally ordered ADMITTED reservation. Later events
// preserve that exact admission and current source-owned release observation.
type EffectReservationEvent struct {
	Sequence uint64                 `json:"sequence"`
	State    EffectReservationState `json:"state"`

	Admission         DispatchAdmissionRecord                     `json:"admission"`
	ReleaseAuthority  contracts.ConnectorReleaseAuthorityEnvelope `json:"release_authority"`
	ReleaseObservedAt time.Time                                   `json:"release_observed_at"`

	AdmittedAt time.Time  `json:"admitted_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	OccurredAt time.Time  `json:"occurred_at"`

	ReasonCode            string `json:"reason_code,omitempty"`
	ConnectorExecutionRef string `json:"connector_execution_ref,omitempty"`
	ProofSessionRef       string `json:"proof_session_ref,omitempty"`
	IntentRef             string `json:"intent_ref,omitempty"`
	EffectRef             string `json:"effect_ref,omitempty"`
}

func (e EffectReservationEvent) Validate() error {
	if e.Sequence == 0 || e.Sequence > contracts.ConnectorReleaseAuthorityMaxRevision {
		return invalidRecord("effect reservation sequence must be a positive JCS-safe integer")
	}
	if err := e.Admission.Validate(); err != nil {
		return invalidRecord("effect reservation admission: " + err.Error())
	}
	if err := e.ReleaseAuthority.Validate(); err != nil {
		return invalidRecord("effect reservation release authority: " + err.Error())
	}
	if err := e.Admission.Admission.ConnectorAuthority.ValidateCurrentRelease(e.ReleaseAuthority.Authority); err != nil {
		return invalidRecord("effect reservation release binding: " + err.Error())
	}
	if e.ReleaseObservedAt.IsZero() || e.AdmittedAt.IsZero() || e.OccurredAt.IsZero() ||
		!isUTC(e.ReleaseObservedAt) || !isUTC(e.AdmittedAt) || !isUTC(e.OccurredAt) {
		return invalidRecord("effect reservation timestamps must use UTC")
	}
	if err := e.ReleaseAuthority.Authority.ValidateAt(e.ReleaseObservedAt); err != nil {
		return invalidRecord("effect reservation observed inactive release authority")
	}
	if e.AdmittedAt.Before(e.Admission.Admission.IssuedAt) || !e.AdmittedAt.Before(e.Admission.Admission.ExpiresAt) ||
		e.OccurredAt.Before(e.AdmittedAt) {
		return invalidRecord("effect reservation timestamps are outside admission lifetime or order")
	}
	for field, value := range map[string]string{
		"reason_code": e.ReasonCode, "connector_execution_ref": e.ConnectorExecutionRef,
		"proof_session_ref": e.ProofSessionRef, "intent_ref": e.IntentRef, "effect_ref": e.EffectRef,
	} {
		if value != "" && (!validToken(value) || len(value) > 512) {
			return invalidRecord("effect reservation " + field + " is invalid")
		}
	}
	switch e.State {
	case EffectReservationStateAdmitted:
		if e.Sequence != 1 || !e.OccurredAt.Equal(e.AdmittedAt) || e.StartedAt != nil || e.ResolvedAt != nil ||
			e.ReasonCode != "" || e.ConnectorExecutionRef != "" || e.ProofSessionRef != "" ||
			e.IntentRef != "" || e.EffectRef != "" {
			return invalidRecord("ADMITTED must be the metadata-free initial reservation event")
		}
	case EffectReservationStateStarted:
		if e.Sequence != 2 || e.StartedAt == nil || !isUTC(*e.StartedAt) || !e.StartedAt.Equal(e.OccurredAt) ||
			e.ResolvedAt != nil || !e.StartedAt.Before(e.Admission.Admission.ExpiresAt) ||
			!validToken(e.ConnectorExecutionRef) {
			return invalidRecord("STARTED must be the second event with an in-lifetime execution reference")
		}
	case EffectReservationStateNotStarted:
		if e.Sequence != 2 || e.StartedAt != nil || e.ResolvedAt == nil || !isUTC(*e.ResolvedAt) ||
			!e.ResolvedAt.Equal(e.OccurredAt) || !validToken(e.ReasonCode) || e.ConnectorExecutionRef != "" {
			return invalidRecord("NOT_STARTED must resolve the initial reservation before connector start")
		}
	case EffectReservationStateUncertain:
		if (e.Sequence != 2 && e.Sequence != 3) || e.ResolvedAt == nil || !isUTC(*e.ResolvedAt) ||
			!e.ResolvedAt.Equal(e.OccurredAt) || !validToken(e.ReasonCode) {
			return invalidRecord("UNCERTAIN must carry a bounded reason and resolution time")
		}
		if e.Sequence == 2 && e.StartedAt != nil {
			return invalidRecord("direct UNCERTAIN transition must not claim a known start time")
		}
		if e.Sequence == 3 && (e.StartedAt == nil || !isUTC(*e.StartedAt) || e.StartedAt.After(*e.ResolvedAt)) {
			return invalidRecord("post-start UNCERTAIN must preserve the earlier start time")
		}
	default:
		return invalidRecord("effect reservation state is unsupported")
	}
	return nil
}

// EffectTransitionMeta supplies bounded evidence references for a durable
// lifecycle transition. Empty references never stand in for proof.
type EffectTransitionMeta struct {
	ReasonCode            string
	ConnectorExecutionRef string
	ProofSessionRef       string
	IntentRef             string
	EffectRef             string
}

func validateEffectTransitionMeta(meta EffectTransitionMeta) error {
	for field, value := range map[string]string{
		"reason_code": meta.ReasonCode, "connector_execution_ref": meta.ConnectorExecutionRef,
		"proof_session_ref": meta.ProofSessionRef, "intent_ref": meta.IntentRef, "effect_ref": meta.EffectRef,
	} {
		if value != "" && (!validToken(value) || len(value) > 512) {
			return fmt.Errorf("%w: %s is invalid", ErrEffectReservationConflict, field)
		}
	}
	return nil
}
