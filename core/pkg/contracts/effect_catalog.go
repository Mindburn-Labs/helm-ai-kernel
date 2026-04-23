package contracts

// EffectTypeCatalog represents the canonical list of effect types.
type EffectTypeCatalog struct {
	CatalogVersion string       `json:"catalog_version"`
	EffectTypes    []EffectType `json:"effect_types"`
}

// EffectType defines a specific capability category.
type EffectType struct {
	TypeID               string         `json:"type_id"` // E.g., DATA_WRITE, FUNDS_TRANSFER
	Name                 string         `json:"name"`
	Description          string         `json:"description,omitempty"`
	Idempotency          IdempotencyRef `json:"idempotency"`
	Classification       Classification `json:"classification"`
	DefaultApprovalLevel string         `json:"default_approval_level,omitempty"` // none, single_human, dual_control, quorum
	RequiresEvidence     bool           `json:"requires_evidence"`
	CompensationRequired bool           `json:"compensation_required"`
	ReceiptSchema        string         `json:"receipt_schema,omitempty"`
}

type IdempotencyRef struct {
	Strategy           string   `json:"strategy"` // client_provided, content_hash, effect_id, none
	KeyComposition     []string `json:"key_composition,omitempty"`
	DedupWindowSeconds int      `json:"dedup_window_seconds,omitempty"`
	OnDuplicate        string   `json:"on_duplicate,omitempty"` // reject, return_existing, log_and_skip
}

type Classification struct {
	Reversibility string `json:"reversibility"` // reversible, compensatable, irreversible
	BlastRadius   string `json:"blast_radius"`  // single_record, dataset, system_wide
	Urgency       string `json:"urgency"`       // deferrable, time_sensitive, immediate
}
