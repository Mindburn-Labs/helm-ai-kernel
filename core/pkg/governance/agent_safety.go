package governance

import ()

// AgentSafetyContext is the runtime fact contract consumed by the built-in
// agent-safety baseline bundle.
type AgentSafetyContext struct {
	EffectType             string
	EffectClass            string
	ToolName               string
	ConnectorID            string
	Action                 string
	Taint                  []string
	SourceTrust            string
	SourceChannel          string
	MemoryTier             string
	MemoryReviewState      string
	MemoryTrustScore       int
	ProvenanceScore        int
	Destination            string
	PayloadBytes           int
	DelegationSessionValid bool
	CredentialScope        string
	A2ASignatureValid      bool
	ManifestDigestValid    bool
	OutputContractValid    bool
	ApprovedArgsValid      bool
	SafeDepState           string
	InspectionOnly         bool
	BudgetRemaining        int
	FanoutCount            int
	RetryCount             int
	PrincipalID            string
	ResourceID             string
}
