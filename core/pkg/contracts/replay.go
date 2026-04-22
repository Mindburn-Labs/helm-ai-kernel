package contracts

type ReplayBundle struct {
	ProposalID    string       `json:"proposal_id"`
	PhenotypeHash string       `json:"phenotype_hash"`
	PolicyProof   *PolicyProof `json:"policy_proof"`
	// Add other fields as needed by Replay
}

type PolicyProof struct {
	Allowed      bool           `json:"allowed"`
	Reason       string         `json:"reason"`
	InputContext map[string]any `json:"input_context"`
	Metrics      map[string]any `json:"metrics"`
	Verdict      string         `json:"verdict"`
	Summary      string         `json:"summary"`
}
