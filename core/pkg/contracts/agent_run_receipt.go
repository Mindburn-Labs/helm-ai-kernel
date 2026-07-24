package contracts

import "time"

const (
	AgentRunReceiptVersion = "agent_run_receipt.v1"

	PolicyProfileWorkstationObserveDraftV1 = "workstation.observe_draft.v1"

	WorkstationEffectModeObserve = "observe"
	WorkstationEffectModeDraft   = "draft"
	WorkstationEffectModeOperate = "operate"

	EffectTypeWorkstationFileDraft       = "WORKSTATION_FILE_DRAFT"
	EffectTypeWorkstationFileWrite       = "WORKSTATION_FILE_WRITE"
	EffectTypeWorkstationShellCommand    = "WORKSTATION_SHELL_COMMAND"
	EffectTypeWorkstationNetworkEgress   = "WORKSTATION_NETWORK_EGRESS"
	EffectTypeWorkstationMCPToolCall     = "WORKSTATION_MCP_TOOL_CALL"
	EffectTypeWorkstationMemoryWrite     = "WORKSTATION_MEMORY_WRITE"
	EffectTypeWorkstationRecurringLoop   = "WORKSTATION_RECURRING_LOOP"
	EffectTypeWorkstationDeployPublish   = "WORKSTATION_DEPLOY_PUBLISH"
	EffectTypeWorkstationSecretRead      = "WORKSTATION_SECRET_READ"
	EffectTypeWorkstationPaymentInitiate = "WORKSTATION_PAYMENT_INITIATE"
	EffectTypeWorkstationValidationRun   = "WORKSTATION_VALIDATION_RUN"
	EffectTypeWorkstationTaintedContext  = "WORKSTATION_TAINTED_CONTEXT"

	WorkstationPermissionNetworkEgress   = "network.egress"
	WorkstationPermissionMCPMutate       = "mcp.mutate"
	WorkstationPermissionMemoryWrite     = "memory.write"
	WorkstationPermissionLoopRegister    = "loop.register"
	WorkstationPermissionShellOperate    = "shell.operate"
	WorkstationPermissionDeployPublish   = "deploy.publish"
	WorkstationPermissionSecretRead      = "secret.read"
	WorkstationPermissionPaymentInitiate = "payment.initiate"

	WorkstationVerdictAllow = "ALLOW"
	WorkstationVerdictDeny  = "DENY"

	// ClientObservationBasis records HOW HELM knows the client ran, which bounds
	// what the receipt is allowed to claim. The distinction is load-bearing: a
	// hook reports what the agent discloses; a parented process constrains what
	// the agent can do. Only the latter earns ClientLoadObserved.
	ClientObservationBasisParentedProcess = "parented_process"
	ClientObservationBasisHookReported    = "hook_reported"
	ClientObservationBasisUnobserved      = "unobserved"
)

// AgentRunReceipt is the public, manifest-first receipt for local workstation
// agent runs. It is observe-only until a downstream enforcement bridge exists.
//
//nolint:govet // field order follows the public JSON contract.
type AgentRunReceipt struct {
	ReceiptVersion       string                     `json:"receipt_version"`
	ReceiptID            string                     `json:"receipt_id"`
	RunID                string                     `json:"run_id"`
	Goal                 string                     `json:"goal"`
	Actor                AgentRunActor              `json:"actor"`
	Workspace            AgentRunWorkspace          `json:"workspace"`
	AgentSurface         string                     `json:"agent_surface"`
	ClientObservation    *ClientObservation         `json:"client_observation,omitempty"`
	PolicyProfile        string                     `json:"policy_profile"`
	ArtifactHashes       map[string]string          `json:"artifact_hashes"`
	ToolActions          []AgentToolAction          `json:"tool_actions"`
	ChangedFiles         []AgentChangedFile         `json:"changed_files"`
	ValidationResults    []AgentValidationResult    `json:"validation_results"`
	MemoryEffects        []AgentMemoryEffect        `json:"memory_effects"`
	RecurringLoopEffects []AgentRecurringLoopEffect `json:"recurring_loop_effects"`
	DeniedEffects        []AgentDeniedEffect        `json:"denied_effects"`
	ProofGraphRefs       []string                   `json:"proofgraph_refs"`
	EvidencePackRefs     []string                   `json:"evidence_pack_refs"`
	CreatedAt            time.Time                  `json:"created_at"`
	CompletedAt          *time.Time                 `json:"completed_at,omitempty"`
	ReceiptHash          string                     `json:"receipt_hash"`
	Signature            string                     `json:"signature"`
	SignerKeyID          string                     `json:"signer_key_id"`
}

type AgentRunActor struct {
	ActorID   string `json:"actor_id"`
	ActorType string `json:"actor_type"`
}

type AgentRunWorkspace struct {
	WorkspaceID string `json:"workspace_id"`
	Path        string `json:"path,omitempty"`
	Repository  string `json:"repository,omitempty"`
}

// ClientObservation records whether HELM actually observed the client process
// load, and on what basis. It is a signed fact: because the whole receipt is
// canonicalized into ReceiptHash and Signature, a mutated ClientObservation
// invalidates the signature.
//
// Before this field existed, "ClientLoadObserved" lived only in prose across
// the docs. A prose assertion about evidence is not evidence. This makes the
// claim a typed value on the receipt that earned it, and Validate refuses the
// combinations that would let a weaker basis assert a stronger fact.
//
// The field is a pointer with omitempty so a receipt that predates it — or a
// run that never observed the client — omits the key entirely and verifies
// byte-identically, exactly as CompletedAt already does.
type ClientObservation struct {
	// ClientLoadObserved is true only when HELM has direct evidence the client
	// process ran under its control. Never true on a hook_reported or
	// unobserved basis; Validate enforces this.
	ClientLoadObserved bool `json:"client_load_observed"`
	// ObservationBasis is one of the ClientObservationBasis* constants and names
	// how HELM knows what it knows.
	ObservationBasis string `json:"observation_basis"`
	// HarnessID is the adapter that ran the client (e.g. "claude", "codex").
	HarnessID string `json:"harness_id,omitempty"`
	// ProcessOwned is true when HELM was the parent process of the client —
	// spawned it, scoped its HOME, scrubbed its env, and supervised it. This is
	// the only basis on which ClientLoadObserved may be true.
	ProcessOwned bool `json:"process_owned"`
}

// Validate rejects a ClientObservation whose claim outruns its basis. A nil
// receiver is valid: absence of observation is a legitimate state, distinct
// from a false claim of one.
func (c *ClientObservation) Validate() error {
	if c == nil {
		return nil
	}
	switch c.ObservationBasis {
	case ClientObservationBasisParentedProcess,
		ClientObservationBasisHookReported,
		ClientObservationBasisUnobserved:
	default:
		return &InvalidClientObservationError{Reason: "unknown observation_basis: " + c.ObservationBasis}
	}
	// ClientLoadObserved is a claim of direct evidence. Only a parented process
	// supplies it; a hook merely relays what the agent chose to disclose.
	if c.ClientLoadObserved && c.ObservationBasis != ClientObservationBasisParentedProcess {
		return &InvalidClientObservationError{
			Reason: "client_load_observed is true but basis is " + c.ObservationBasis + "; only parented_process observes the load",
		}
	}
	// ProcessOwned IS the parented_process basis; the two cannot disagree.
	if c.ProcessOwned && c.ObservationBasis != ClientObservationBasisParentedProcess {
		return &InvalidClientObservationError{
			Reason: "process_owned is true but basis is " + c.ObservationBasis,
		}
	}
	// An observed load must name the harness that produced it — an anonymous
	// observation cannot be corroborated against the run.
	if c.ClientLoadObserved && c.HarnessID == "" {
		return &InvalidClientObservationError{Reason: "client_load_observed is true but harness_id is empty"}
	}
	return nil
}

// InvalidClientObservationError is returned by ClientObservation.Validate when a
// claim outruns its basis.
type InvalidClientObservationError struct{ Reason string }

func (e *InvalidClientObservationError) Error() string {
	return "invalid client observation: " + e.Reason
}

// AgentToolAction is a normalized workstation tool event. Actions may be
// imported from Codex/Claude Code event streams, hooks, OTel logs, or a
// manifest-first tool-events.ndjson file.
//
//nolint:govet // field order follows timeline readability.
type AgentToolAction struct {
	ActionID    string            `json:"action_id"`
	ToolID      string            `json:"tool_id"`
	Action      string            `json:"action"`
	EffectType  string            `json:"effect_type"`
	EffectMode  string            `json:"effect_mode"`
	Status      string            `json:"status"`
	Verdict     string            `json:"verdict"`
	ReasonCode  string            `json:"reason_code,omitempty"`
	Target      string            `json:"target,omitempty"`
	OccurredAt  time.Time         `json:"occurred_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	TaintLabels []string          `json:"taint_labels,omitempty"`
}

type AgentChangedFile struct {
	Path      string `json:"path"`
	Status    string `json:"status"`
	Additions int    `json:"additions,omitempty"`
	Deletions int    `json:"deletions,omitempty"`
}

// AgentValidationResult records command output by hash so receipt consumers do
// not need raw stdout/stderr or chat history to verify the run summary.
type AgentValidationResult struct {
	Command     string     `json:"command"`
	ExitCode    int        `json:"exit_code"`
	Status      string     `json:"status"`
	StdoutHash  string     `json:"stdout_hash,omitempty"`
	StderrHash  string     `json:"stderr_hash,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// AgentMemoryEffect models durable memory as an effect with retention and
// sensitivity, rather than treating memory as implicit conversation state.
type AgentMemoryEffect struct {
	EffectID     string   `json:"effect_id"`
	MemoryClass  string   `json:"memory_class"`
	DataClass    string   `json:"data_class"`
	Sensitivity  string   `json:"sensitivity"`
	TTLDays      uint32   `json:"ttl_days"`
	ContentHash  string   `json:"content_hash"`
	ContentRef   string   `json:"content_ref,omitempty"`
	Purpose      string   `json:"purpose,omitempty"`
	ReviewState  string   `json:"review_state,omitempty"`
	Verdict      string   `json:"verdict"`
	ReasonCode   string   `json:"reason_code,omitempty"`
	TaintLabels  []string `json:"taint_labels,omitempty"`
	ObservedOnly bool     `json:"observed_only"`
}

// AgentRecurringLoopEffect is the public receipt shape for a scheduled agent
// loop. M2 imports and records these; M3+ decides whether to enforce them.
type AgentRecurringLoopEffect struct {
	EffectID     string    `json:"effect_id"`
	Schedule     string    `json:"schedule"`
	MaxRuntime   string    `json:"max_runtime"`
	ToolScope    []string  `json:"tool_scope"`
	ExpiresAt    time.Time `json:"expires_at"`
	Verdict      string    `json:"verdict"`
	ReasonCode   string    `json:"reason_code,omitempty"`
	ObservedOnly bool      `json:"observed_only"`
}

type AgentDeniedEffect struct {
	EffectID   string    `json:"effect_id"`
	EffectType string    `json:"effect_type"`
	ToolID     string    `json:"tool_id,omitempty"`
	Action     string    `json:"action,omitempty"`
	ReasonCode string    `json:"reason_code"`
	Reason     string    `json:"reason,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

// WorkstationPolicyDecisionReceipt is the selected-effect enforcement bridge
// receipt. It records the decision that a CLI wrapper or local hook must obey.
//
// M3 covers selected workstation effect classes only. A DENY receipt means HELM
// refused to authorize the wrapper/hook execution path; it does not claim full
// desktop or proprietary-hosted-agent control.
type WorkstationPolicyDecisionReceipt struct {
	ReceiptVersion string                     `json:"receipt_version"`
	DecisionID     string                     `json:"decision_id"`
	Request        WorkstationDecisionRequest `json:"request"`
	PolicyProfile  string                     `json:"policy_profile"`
	Verdict        string                     `json:"verdict"`
	ReasonCode     string                     `json:"reason_code,omitempty"`
	Reason         string                     `json:"reason,omitempty"`
	ObservedOnly   bool                       `json:"observed_only"`
	CreatedAt      time.Time                  `json:"created_at"`
	ReceiptHash    string                     `json:"receipt_hash"`
	Signature      string                     `json:"signature"`
	SignerKeyID    string                     `json:"signer_key_id"`
}

type WorkstationDecisionRequest struct {
	RequestID    string            `json:"request_id"`
	RunID        string            `json:"run_id,omitempty"`
	ActorID      string            `json:"actor_id,omitempty"`
	WorkspaceID  string            `json:"workspace_id,omitempty"`
	AgentSurface string            `json:"agent_surface,omitempty"`
	ToolID       string            `json:"tool_id"`
	Action       string            `json:"action"`
	EffectType   string            `json:"effect_type"`
	EffectMode   string            `json:"effect_mode"`
	Target       string            `json:"target,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	OccurredAt   time.Time         `json:"occurred_at"`
}

type WorkstationPolicyProfile struct {
	ID      string                     `json:"id"`
	Mode    string                     `json:"mode"`
	Observe WorkstationObservePolicy   `json:"observe"`
	Draft   WorkstationDraftPolicy     `json:"draft"`
	Operate WorkstationOperatePolicy   `json:"operate"`
	Egress  WorkstationEgressPolicy    `json:"egress"`
	Memory  WorkstationMemoryPolicy    `json:"memory"`
	Loops   WorkstationRecurringPolicy `json:"recurring_loops"`
}

type WorkstationObservePolicy struct {
	AllowedActions []string `json:"allowed_actions"`
}

type WorkstationDraftPolicy struct {
	WorkspaceRoots          []string `json:"workspace_roots"`
	AllowGeneratedArtifacts bool     `json:"allow_generated_artifacts"`
}

type WorkstationOperatePolicy struct {
	Permissions []string `json:"permissions"`
}

type WorkstationEgressPolicy struct {
	Allowlist []WorkstationEgressDestination `json:"allowlist"`
}

type WorkstationEgressDestination struct {
	Host     string `json:"host"`
	Protocol string `json:"protocol"`
}

type WorkstationMemoryPolicy struct {
	DefaultTTLDays uint32   `json:"default_ttl_days"`
	MaxTTLDays     uint32   `json:"max_ttl_days,omitempty"`
	AllowedClasses []string `json:"allowed_classes"`
}

type WorkstationRecurringPolicy struct {
	RequireSchedule   bool `json:"require_schedule"`
	RequireMaxRuntime bool `json:"require_max_runtime"`
	RequireToolScope  bool `json:"require_tool_scope"`
	RequireExpiration bool `json:"require_expiration"`
}
