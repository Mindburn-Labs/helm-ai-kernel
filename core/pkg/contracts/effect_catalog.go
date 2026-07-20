package contracts

import "encoding/json"

// EffectTypeCatalog represents the canonical list of effect types.
type EffectTypeCatalog struct {
	CatalogVersion string       `json:"catalog_version"`
	EffectTypes    []EffectType `json:"effect_types"`
}

// EffectType defines a specific capability category.
type EffectType struct {
	TypeID                      string         `json:"type_id"` // E.g., DATA_WRITE, FUNDS_TRANSFER
	Name                        string         `json:"name"`
	Description                 string         `json:"description,omitempty"`
	Status                      string         `json:"status,omitempty"` // preview, normative, deprecated
	Taxon                       string         `json:"taxon,omitempty"`  // E0-E4
	BaseEffectTypes             []string       `json:"base_effect_types,omitempty"`
	Idempotency                 IdempotencyRef `json:"idempotency"`
	Classification              Classification `json:"classification"`
	DefaultApprovalLevel        string         `json:"default_approval_level,omitempty"` // Risk baseline only; Authority Court remains the sole authorization source.
	RequiresEvidence            bool           `json:"requires_evidence"`
	CompensationRequired        bool           `json:"compensation_required"`
	CompensationEffectType      string         `json:"compensation_effect_type,omitempty"`
	CompensationAuthorization   string         `json:"compensation_authorization,omitempty"`
	InputSchema                 string         `json:"input_schema,omitempty"`
	AuthorizationEnvelopeSchema string         `json:"authorization_envelope_schema,omitempty"`
	ReceiptSchema               string         `json:"receipt_schema,omitempty"`
	ConnectorID                 string         `json:"connector_id,omitempty"`
	ActionURN                   string         `json:"action_urn,omitempty"`
	PreflightRequired           bool           `json:"preflight_required,omitempty"`
	TwoPhaseCommitRequired      bool           `json:"two_phase_commit_required,omitempty"`
	MinEvidenceGrade            string         `json:"min_evidence_grade,omitempty"`
	PolicyHooks                 []string       `json:"policy_hooks,omitempty"`
}

type IdempotencyRef struct {
	Strategy           string   `json:"strategy"` // client_provided, content_hash, effect_id, none
	KeyComposition     []string `json:"key_composition"`
	DedupWindowSeconds int      `json:"dedup_window_seconds,omitempty"`
	OnDuplicate        string   `json:"on_duplicate,omitempty"` // reject, return_existing, log_and_skip
}

// MarshalJSON keeps the schema-required key composition explicit on the wire.
// Strategies without component fields serialize an empty array rather than
// omitting the field or emitting null.
func (ref IdempotencyRef) MarshalJSON() ([]byte, error) {
	type idempotencyWire struct {
		Strategy           string   `json:"strategy"`
		KeyComposition     []string `json:"key_composition"`
		DedupWindowSeconds int      `json:"dedup_window_seconds,omitempty"`
		OnDuplicate        string   `json:"on_duplicate,omitempty"`
	}
	keyComposition := append([]string{}, ref.KeyComposition...)
	return json.Marshal(idempotencyWire{
		Strategy:           ref.Strategy,
		KeyComposition:     keyComposition,
		DedupWindowSeconds: ref.DedupWindowSeconds,
		OnDuplicate:        ref.OnDuplicate,
	})
}

type Classification struct {
	Reversibility string `json:"reversibility"` // reversible, compensatable, irreversible
	BlastRadius   string `json:"blast_radius"`  // single_record, dataset, system_wide
	Urgency       string `json:"urgency"`       // deferrable, time_sensitive, immediate
}
