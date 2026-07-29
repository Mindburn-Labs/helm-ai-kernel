package contracts

import (
	"encoding/json"
	"errors"
	"time"
)

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

	// Finality and Counterfactual are opt-in per policy profile and absent
	// (not empty) when disabled: their presence is itself a policy statement.
	Finality       DenialFinality        `json:"finality,omitempty"`
	Counterfactual *DenialCounterfactual `json:"counterfactual,omitempty"`
}

// DenialFinality tells a consumer what kind of "no" it received, so an agent
// can draw the right lesson from it: which bounds to record, which to erase,
// and which refusals were never about the attempted action at all.
//
// It is derived from the reason code that fired, never assigned by a caller.
type DenialFinality string

const (
	// DenialClassForbidden: the action itself is forbidden by policy. A
	// consumer should erase any stored bounds for it and stop probing.
	DenialClassForbidden DenialFinality = "class_forbidden"
	// DenialUngranted: no grant is configured for this action. Nothing to
	// retry and no bound to learn — the action needs an authority to say yes.
	// The kernel PDP carries this on the escalation channel with the required
	// signers; the workstation layer has no approver, so it is terminal here.
	DenialUngranted DenialFinality = "ungranted"
	// DenialInstanceParameter: a bound was exceeded. A consumer should record
	// the bound and retry within it.
	DenialInstanceParameter DenialFinality = "instance_parameter"
	// DenialInstanceContext: the surrounding context was refused (taint, for
	// example). The refusal was not about the action; a consumer should touch
	// none of its stored bounds.
	DenialInstanceContext DenialFinality = "instance_context"
	// DenialInstanceMembership: a caller-chosen target was refused against a
	// confidential set — an egress host outside the allowlist, a path outside
	// the workspace roots. That target is closed; other targets may work. The
	// set is never disclosed, so there is no bound to record and nothing to
	// erase: stop retrying this target without unlearning anything else.
	//
	// Distinct from DenialClassForbidden, where the refused thing is a
	// policy-named category of action from a fixed public vocabulary rather
	// than a probe against a set the policy keeps private.
	DenialInstanceMembership DenialFinality = "instance_membership"
)

// DenialCounterfactual is the nearest allowed envelope for a denial: enough for
// an agent to retry correctly, and no more.
//
// It is emitted for scalar bounds and required-capability names only. Denials
// that turn on set membership never carry one — an egress allowlist or a set of
// workspace roots is a map of internal infrastructure, and disclosing it would
// turn every denial into a free probe. The workstation producer derives this
// through its evaluator-owned AnnotateDenial entry point.
//
// Despite the shared word, this is not a CounterfactualReceipt. This value
// rides a denial the boundary actually enforced and describes the nearest
// request that would have been allowed. A CounterfactualReceipt records the
// verdict the PDP would have issued under an observe grant, enforces nothing,
// and must never be presentable as enforced.
type DenialCounterfactual struct {
	// Field is the policy field that bound the request, e.g. "ttl_days".
	Field string `json:"field"`
	// Requested and Max describe a scalar bound. When Capability is empty,
	// MarshalJSON emits both values — including zero — so the wire shape is
	// never ambiguous.
	Requested uint32 `json:"requested,omitempty"`
	Max       uint32 `json:"max,omitempty"`
	// Capability names the permission the action would have needed.
	Capability string `json:"capability,omitempty"`
}

func (c DenialCounterfactual) Validate() error {
	if c.Field == "" {
		return errors.New("denial counterfactual field is required")
	}
	if c.Capability != "" && (c.Requested != 0 || c.Max != 0) {
		return errors.New("denial counterfactual cannot mix a scalar bound and capability")
	}
	if c.Capability != "" && !IsWorkstationPermission(c.Capability) {
		return errors.New("denial counterfactual capability is not in the workstation permission vocabulary")
	}
	return nil
}

func (c DenialCounterfactual) MarshalJSON() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Capability != "" {
		return json.Marshal(struct {
			Field      string `json:"field"`
			Capability string `json:"capability"`
		}{c.Field, c.Capability})
	}
	return json.Marshal(struct {
		Field     string `json:"field"`
		Requested uint32 `json:"requested"`
		Max       uint32 `json:"max"`
	}{c.Field, c.Requested, c.Max})
}

func (c *DenialCounterfactual) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for name := range fields {
		switch name {
		case "field", "requested", "max", "capability":
		default:
			return errors.New("denial counterfactual contains an unknown field")
		}
	}

	var wire struct {
		Field      string  `json:"field"`
		Requested  *uint32 `json:"requested"`
		Max        *uint32 `json:"max"`
		Capability *string `json:"capability"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	_, hasRequested := fields["requested"]
	_, hasMax := fields["max"]
	_, hasCapability := fields["capability"]
	hasScalar := hasRequested || hasMax
	if hasScalar == hasCapability {
		return errors.New("denial counterfactual must contain exactly one scalar bound or capability")
	}
	if hasScalar && (!hasRequested || !hasMax || wire.Requested == nil || wire.Max == nil) {
		return errors.New("denial counterfactual scalar bound requires requested and max")
	}
	if hasCapability && (wire.Capability == nil || !IsWorkstationPermission(*wire.Capability)) {
		return errors.New("denial counterfactual capability is not in the workstation permission vocabulary")
	}

	decoded := DenialCounterfactual{Field: wire.Field}
	if hasCapability {
		decoded.Capability = *wire.Capability
	} else {
		decoded.Requested = *wire.Requested
		decoded.Max = *wire.Max
	}
	if err := decoded.Validate(); err != nil {
		return err
	}
	*c = decoded
	return nil
}

// IsWorkstationPermission reports whether name belongs to the fixed public
// permission vocabulary that a denial counterfactual may disclose.
func IsWorkstationPermission(name string) bool {
	switch name {
	case WorkstationPermissionNetworkEgress,
		WorkstationPermissionMCPMutate,
		WorkstationPermissionMemoryWrite,
		WorkstationPermissionLoopRegister,
		WorkstationPermissionShellOperate,
		WorkstationPermissionDeployPublish,
		WorkstationPermissionSecretRead,
		WorkstationPermissionPaymentInitiate:
		return true
	}
	return false
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
	// Learning is nil unless a profile opts in, which keeps the receipts of
	// every existing profile byte-identical.
	Learning *WorkstationLearningPolicy `json:"learning,omitempty"`
}

// WorkstationLearningPolicy opts a profile into the denial fields an agent can
// learn from. Both default off. They are separate switches because they
// disclose different things: finality is a taxonomy, a counterfactual is a
// policy value.
type WorkstationLearningPolicy struct {
	EmitFinality       bool `json:"emit_finality,omitempty"`
	EmitCounterfactual bool `json:"emit_counterfactual,omitempty"`
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
