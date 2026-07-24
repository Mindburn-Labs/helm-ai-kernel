package agentruntime

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// SchemaVersionV1 is the only turn-event schema version this package
// reads or writes.
const SchemaVersionV1 = 1

// EventType discriminates the versioned turn-event union. The set is
// HELM-native; it covers lifecycle, model, tool, permission, and toolset
// extension events.
type EventType string

const (
	// Lifecycle.
	EventTurnCreated   EventType = "turn_created"
	EventTurnSuspended EventType = "turn_suspended"
	EventTurnResumed   EventType = "turn_resumed"
	EventTurnCompleted EventType = "turn_completed"
	EventTurnFailed    EventType = "turn_failed"
	EventTurnCancelled EventType = "turn_cancelled"

	// Model.
	EventModelCallRequested EventType = "model_call_requested"
	EventModelCallCompleted EventType = "model_call_completed"
	EventModelCallFailed    EventType = "model_call_failed"

	// Permission (advisory records; authority stays with kernel verdicts).
	EventToolPermissionRequired EventType = "tool_permission_required"
	EventToolPermissionResolved EventType = "tool_permission_resolved"

	// Tool.
	EventToolInvocationRequested EventType = "tool_invocation_requested"
	EventToolResult              EventType = "tool_result"

	// Toolset extension.
	EventToolsExtended EventType = "tools_extended"
)

// Message roles.
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
)

// Tool invocation modes.
const (
	ModeSync  = "sync"
	ModeAsync = "async"
)

// Tool result statuses.
const (
	ResultOK            = "ok"
	ResultError         = "error"
	ResultIndeterminate = "indeterminate"
)

// Permission decisions.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

// Model call failure classes.
const (
	FailProvider        = "provider"
	FailInterrupted     = "interrupted"
	FailTimeout         = "timeout"
	FailInvalidResponse = "invalid_response"
)

// Stop reasons for a completed model call.
const (
	StopEndTurn       = "end_turn"
	StopToolCalls     = "tool_calls"
	StopLength        = "length"
	StopContentFilter = "content_filter"
)

var (
	turnIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	toolCallIDPattern = regexp.MustCompile(`^[^\s]{1,128}$`)
	sha256Prefix      = "sha256:"
)

// ModelRef identifies the concrete model targeted by a turn or call.
type ModelRef struct {
	Provider string `json:"provider"`
	Name     string `json:"name"`
}

// ModelParams carries the request-time sampling parameters. Pointers keep
// "unset" distinguishable from zero so canonical bytes stay stable.
type ModelParams struct {
	Temperature     *float64 `json:"temperature,omitempty"`
	MaxTokens       *int     `json:"max_tokens,omitempty"`
	ReasoningEffort string   `json:"reasoning_effort,omitempty"`
}

// Usage is token accounting for one model call or a whole turn.
type Usage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

// ToolCall is a model-requested tool invocation inside an assistant
// message. Args are kept raw and canonicalized for hashing.
type ToolCall struct {
	ToolCallID string          `json:"tool_call_id"`
	ToolID     string          `json:"tool_id"`
	Args       json.RawMessage `json:"args"`
}

// Message is one durable conversation message.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"` // role=="tool" only
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`   // role=="assistant" only
}

// ToolDescriptor is the durable, prompt-facing description of one tool.
// RequiresPermission travels with the descriptor (fail-closed by
// construction): a tool that declares it may only be invoked after an
// allow decision is durable.
type ToolDescriptor struct {
	ToolID             string `json:"tool_id"`
	Description        string `json:"description"`
	RequiresPermission bool   `json:"requires_permission"`
}

// --- Payloads. Exactly one payload pointer is non-nil per Event, and it
// must match Event.Type. ---

// TurnCreated opens a turn. It is always seq 0.
type TurnCreated struct {
	AgentID           string           `json:"agent_id"`
	AgentSnapshotHash string           `json:"agent_snapshot_hash,omitempty"` // sha256 of composed instructions+tools
	Model             ModelRef         `json:"model"`
	MaxModelCalls     int              `json:"max_model_calls"` // model-call budget, >= 1
	Input             []Message        `json:"input"`
	Tools             []ToolDescriptor `json:"tools"` // base toolset snapshot
	ContextTurnID     string           `json:"context_turn_id,omitempty"`
}

// ModelCallRequested records intent to call the model. It stores
// references, never payload: ComposeRequest recomposes exact bytes.
type ModelCallRequested struct {
	CallIndex        int         `json:"call_index"`
	Model            ModelRef    `json:"model"`
	Params           ModelParams `json:"params"`
	MessageRefs      []string    `json:"message_refs"` // "input" | "assistant:<n>" | "tool_result:<id>"
	ToolSnapshotHash string      `json:"tool_snapshot_hash,omitempty"`
}

// ModelCallCompleted closes an open model call with the assistant output.
type ModelCallCompleted struct {
	CallIndex        int     `json:"call_index"`
	Message          Message `json:"message"` // role must be "assistant"
	Usage            Usage   `json:"usage"`
	StopReason       string  `json:"stop_reason"`
	ProviderDataHash string  `json:"provider_data_hash,omitempty"` // hash of provider-signed parts
}

// ModelCallFailed closes an open model call without assistant output.
type ModelCallFailed struct {
	CallIndex int    `json:"call_index"`
	Class     string `json:"class"` // Fail* constants
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// ToolPermissionRequired records that a tool call needs a decision before
// invocation. Advisory: the authoritative decision is a kernel verdict.
type ToolPermissionRequired struct {
	ToolCallID  string `json:"tool_call_id"`
	ToolID      string `json:"tool_id"`
	Requirement string `json:"requirement"` // e.g. "kernel-verdict", "command-allowlist", "file-boundary", "human-approval"
	Detail      string `json:"detail,omitempty"`
}

// ToolPermissionResolved records the decision for one tool call.
// VerdictRef points at the kernel decision/receipt that carries actual
// authority; this event never authorizes anything by itself.
type ToolPermissionResolved struct {
	ToolCallID string `json:"tool_call_id"`
	Decision   string `json:"decision"` // DecisionAllow | DecisionDeny
	DecidedBy  string `json:"decided_by"`
	VerdictRef string `json:"verdict_ref,omitempty"`
}

// ToolInvocationRequested records the dispatch of one tool call. ArgsHash
// binds the canonical args at request time; ReceiptRef links the kernel
// receipt produced by the governed effect, when one exists.
type ToolInvocationRequested struct {
	ToolCallID string          `json:"tool_call_id"`
	ToolID     string          `json:"tool_id"`
	Args       json.RawMessage `json:"args"`
	ArgsHash   string          `json:"args_hash"`
	Mode       string          `json:"mode"` // ModeSync | ModeAsync
	ReceiptRef string          `json:"receipt_ref,omitempty"`
}

// ToolResult closes one tool call. Status "indeterminate" means the call
// may have executed but the outcome is unknown (crash recovery); an
// indeterminate call is never re-executed.
type ToolResult struct {
	ToolCallID string `json:"tool_call_id"`
	Status     string `json:"status"` // Result* constants
	Content    string `json:"content"`
	ReceiptRef string `json:"receipt_ref,omitempty"`
}

// ToolsExtended extends the toolset mid-turn (e.g. a skill attaching
// tools). Extensions apply only to model calls at or after
// FirstAffectedModelCallIndex; historical calls reconstruct with their
// historical toolsets.
type ToolsExtended struct {
	Tools                       []ToolDescriptor `json:"tools"`
	FirstAffectedModelCallIndex int              `json:"first_affected_model_call_index"`
	Source                      string           `json:"source"`
}

// TurnSuspended snapshots all pending work so a crash-safe resume can
// distinguish "still waiting" from "interrupted".
type TurnSuspended struct {
	Reason                           string   `json:"reason"`
	PendingAsyncToolCallIDs          []string `json:"pending_async_tool_call_ids"`
	OutstandingPermissionToolCallIDs []string `json:"outstanding_permission_tool_call_ids"`
}

// TurnResumed marks an explicit resume from suspension.
type TurnResumed struct {
	Reason string `json:"reason"`
}

// TurnCompleted terminates a turn successfully.
type TurnCompleted struct {
	Outcome string `json:"outcome"`
	Usage   Usage  `json:"usage"`
}

// TurnFailed terminates a turn with a failure.
type TurnFailed struct {
	Class   string `json:"class"`
	Message string `json:"message"`
}

// TurnCancelled terminates a turn by cancellation. Cancellation is always
// legal from any non-terminal state and materializes no live dependency.
type TurnCancelled struct {
	Reason string `json:"reason"`
}

// Event is the versioned, hash-chained turn-log record. Seq is the 0-based
// position within the turn. PrevHash is the HashEvent of the previous
// event, or "" for seq 0; it is part of the hashed content, so the chain
// is self-binding.
type Event struct {
	SchemaVersion int       `json:"schema_version"`
	TurnID        string    `json:"turn_id"`
	Seq           uint64    `json:"seq"`
	Type          EventType `json:"type"`
	At            time.Time `json:"at"`
	PrevHash      string    `json:"prev_hash"`

	Created       *TurnCreated             `json:"turn_created,omitempty"`
	Suspended     *TurnSuspended           `json:"turn_suspended,omitempty"`
	Resumed       *TurnResumed             `json:"turn_resumed,omitempty"`
	Completed     *TurnCompleted           `json:"turn_completed,omitempty"`
	Failed        *TurnFailed              `json:"turn_failed,omitempty"`
	Cancelled     *TurnCancelled           `json:"turn_cancelled,omitempty"`
	CallRequested *ModelCallRequested      `json:"model_call_requested,omitempty"`
	CallCompleted *ModelCallCompleted      `json:"model_call_completed,omitempty"`
	CallFailed    *ModelCallFailed         `json:"model_call_failed,omitempty"`
	PermRequired  *ToolPermissionRequired  `json:"tool_permission_required,omitempty"`
	PermResolved  *ToolPermissionResolved  `json:"tool_permission_resolved,omitempty"`
	InvRequested  *ToolInvocationRequested `json:"tool_invocation_requested,omitempty"`
	ToolResult    *ToolResult              `json:"tool_result,omitempty"`
	ToolsExtended *ToolsExtended           `json:"tools_extended,omitempty"`
}

// NewEvent constructs an event envelope with the schema version filled in
// and the timestamp normalized to UTC. The caller sets exactly one payload
// pointer; the store assigns Seq and PrevHash at append time.
func NewEvent(turnID string, typ EventType, at time.Time) Event {
	return Event{
		SchemaVersion: SchemaVersionV1,
		TurnID:        turnID,
		Type:          typ,
		At:            at.UTC(),
	}
}

// HashEvent returns "sha256:" + hex(SHA-256(RFC 8785 canonical JSON of e)).
// The hash covers PrevHash, which is what makes the log a chain.
func HashEvent(e *Event) (string, error) {
	h, err := canonicalize.CanonicalHash(e)
	if err != nil {
		return "", fmt.Errorf("agentruntime: hash event: %w", err)
	}
	return sha256Prefix + h, nil
}

// CanonicalBytes returns the RFC 8785 canonical JSON encoding of e — the
// exact byte form stored in the turn log.
func CanonicalBytes(e *Event) ([]byte, error) {
	b, err := canonicalize.JCS(e)
	if err != nil {
		return nil, fmt.Errorf("agentruntime: canonicalize event: %w", err)
	}
	return b, nil
}

// ComputeArgsHash binds tool args at request time:
// "sha256:" + hex(SHA-256(RFC 8785 canonical JSON of args)).
func ComputeArgsHash(args json.RawMessage) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("agentruntime: empty tool args")
	}
	h, err := canonicalize.CanonicalHash(args)
	if err != nil {
		return "", fmt.Errorf("agentruntime: hash tool args: %w", err)
	}
	return sha256Prefix + h, nil
}

// IsSHA256Hash reports whether s is "sha256:" followed by 64 lowercase
// hex characters.
func IsSHA256Hash(s string) bool {
	if !strings.HasPrefix(s, sha256Prefix) {
		return false
	}
	d := s[len(sha256Prefix):]
	if len(d) != 64 {
		return false
	}
	_, err := hex.DecodeString(d)
	return err == nil && d == strings.ToLower(d)
}

// payloadFor returns the payload pointer that must be set for typ, and
// checks that no other payload is set.
func (e *Event) payloadFor() (interface{}, error) {
	var want interface{}
	switch e.Type {
	case EventTurnCreated:
		want = e.Created
	case EventTurnSuspended:
		want = e.Suspended
	case EventTurnResumed:
		want = e.Resumed
	case EventTurnCompleted:
		want = e.Completed
	case EventTurnFailed:
		want = e.Failed
	case EventTurnCancelled:
		want = e.Cancelled
	case EventModelCallRequested:
		want = e.CallRequested
	case EventModelCallCompleted:
		want = e.CallCompleted
	case EventModelCallFailed:
		want = e.CallFailed
	case EventToolPermissionRequired:
		want = e.PermRequired
	case EventToolPermissionResolved:
		want = e.PermResolved
	case EventToolInvocationRequested:
		want = e.InvRequested
	case EventToolResult:
		want = e.ToolResult
	case EventToolsExtended:
		want = e.ToolsExtended
	default:
		return nil, fmt.Errorf("unknown event type %q", e.Type)
	}
	set := 0
	for _, p := range []interface{}{
		e.Created, e.Suspended, e.Resumed, e.Completed, e.Failed, e.Cancelled,
		e.CallRequested, e.CallCompleted, e.CallFailed,
		e.PermRequired, e.PermResolved, e.InvRequested, e.ToolResult, e.ToolsExtended,
	} {
		if !isNilPtr(p) {
			set++
		}
	}
	if isNilPtr(want) {
		return nil, fmt.Errorf("missing payload for event type %q", e.Type)
	}
	if set != 1 {
		return nil, fmt.Errorf("event type %q must carry exactly its own payload, found %d payloads", e.Type, set)
	}
	return want, nil
}

// isNilPtr reports whether p is an interface holding a nil pointer (all
// event payloads are pointer types).
func isNilPtr(p interface{}) bool {
	if p == nil {
		return true
	}
	v := reflect.ValueOf(p)
	return v.Kind() == reflect.Ptr && v.IsNil()
}

// Validate checks an event in isolation: schema version, envelope fields,
// type/payload agreement, and per-payload field rules. It does not check
// sequencing or chain position — that is the reducer's and store's job.
func (e *Event) Validate() error {
	if e.SchemaVersion != SchemaVersionV1 {
		return fmt.Errorf("unsupported schema_version %d (want %d)", e.SchemaVersion, SchemaVersionV1)
	}
	if !turnIDPattern.MatchString(e.TurnID) {
		return fmt.Errorf("invalid turn_id %q", e.TurnID)
	}
	if e.At.IsZero() {
		return fmt.Errorf("missing event timestamp")
	}
	if e.PrevHash != "" && !IsSHA256Hash(e.PrevHash) {
		return fmt.Errorf("malformed prev_hash")
	}
	p, err := e.payloadFor()
	if err != nil {
		return err
	}
	switch v := p.(type) {
	case *TurnCreated:
		return v.validate()
	case *ModelCallRequested:
		return v.validate()
	case *ModelCallCompleted:
		return v.validate()
	case *ModelCallFailed:
		return v.validate()
	case *ToolPermissionRequired:
		return v.validate()
	case *ToolPermissionResolved:
		return v.validate()
	case *ToolInvocationRequested:
		return v.validate()
	case *ToolResult:
		return v.validate()
	case *ToolsExtended:
		return v.validate()
	case *TurnSuspended:
		return v.validate()
	case *TurnResumed:
		return v.validate()
	case *TurnCompleted:
		return v.validate()
	case *TurnFailed:
		return v.validate()
	case *TurnCancelled:
		return v.validate()
	default:
		return fmt.Errorf("unhandled payload type %T", p)
	}
}

func validModel(m ModelRef) error {
	if m.Provider == "" || m.Name == "" {
		return fmt.Errorf("model requires provider and name")
	}
	return nil
}

func validToolCallID(id string) error {
	if !toolCallIDPattern.MatchString(id) {
		return fmt.Errorf("invalid tool_call_id %q", id)
	}
	return nil
}

func validMessage(m Message) error {
	switch m.Role {
	case RoleSystem, RoleUser:
		if m.Content == "" {
			return fmt.Errorf("%s message requires content", m.Role)
		}
		if len(m.ToolCalls) > 0 || m.ToolCallID != "" {
			return fmt.Errorf("%s message must not carry tool fields", m.Role)
		}
	case RoleAssistant:
		if m.Content == "" && len(m.ToolCalls) == 0 {
			return fmt.Errorf("assistant message requires content or tool calls")
		}
		if m.ToolCallID != "" {
			return fmt.Errorf("assistant message must not carry tool_call_id")
		}
		seen := map[string]bool{}
		for _, tc := range m.ToolCalls {
			if err := validToolCallID(tc.ToolCallID); err != nil {
				return err
			}
			if tc.ToolID == "" {
				return fmt.Errorf("tool call %q missing tool_id", tc.ToolCallID)
			}
			if len(tc.Args) == 0 || !json.Valid(tc.Args) {
				return fmt.Errorf("tool call %q has invalid args", tc.ToolCallID)
			}
			if seen[tc.ToolCallID] {
				return fmt.Errorf("duplicate tool_call_id %q in assistant message", tc.ToolCallID)
			}
			seen[tc.ToolCallID] = true
		}
	case RoleTool:
		if err := validToolCallID(m.ToolCallID); err != nil {
			return err
		}
		if len(m.ToolCalls) > 0 {
			return fmt.Errorf("tool message must not carry tool_calls")
		}
	default:
		return fmt.Errorf("unknown message role %q", m.Role)
	}
	return nil
}

func validToolDescriptors(tools []ToolDescriptor) error {
	seen := map[string]bool{}
	for _, t := range tools {
		if t.ToolID == "" {
			return fmt.Errorf("tool descriptor missing tool_id")
		}
		if t.Description == "" {
			return fmt.Errorf("tool %q missing description", t.ToolID)
		}
		if seen[t.ToolID] {
			return fmt.Errorf("duplicate tool_id %q", t.ToolID)
		}
		seen[t.ToolID] = true
	}
	return nil
}

func (p *TurnCreated) validate() error {
	if p.AgentID == "" {
		return fmt.Errorf("turn_created requires agent_id")
	}
	if p.AgentSnapshotHash != "" && !IsSHA256Hash(p.AgentSnapshotHash) {
		return fmt.Errorf("malformed agent_snapshot_hash")
	}
	if err := validModel(p.Model); err != nil {
		return err
	}
	if p.MaxModelCalls < 1 {
		return fmt.Errorf("max_model_calls must be >= 1")
	}
	if len(p.Input) == 0 {
		return fmt.Errorf("turn_created requires at least one input message")
	}
	for _, m := range p.Input {
		if err := validMessage(m); err != nil {
			return err
		}
	}
	if err := validToolDescriptors(p.Tools); err != nil {
		return err
	}
	if p.ContextTurnID != "" && !turnIDPattern.MatchString(p.ContextTurnID) {
		return fmt.Errorf("invalid context_turn_id %q", p.ContextTurnID)
	}
	return nil
}

// ValidMessageRef reports whether ref has a legal reference form.
func ValidMessageRef(ref string) bool {
	if ref == "input" {
		return true
	}
	if strings.HasPrefix(ref, "assistant:") {
		n := strings.TrimPrefix(ref, "assistant:")
		if n == "" {
			return false
		}
		for _, r := range n {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(ref, "tool_result:") {
		return toolCallIDPattern.MatchString(strings.TrimPrefix(ref, "tool_result:"))
	}
	return false
}

func (p *ModelCallRequested) validate() error {
	if p.CallIndex < 0 {
		return fmt.Errorf("call_index must be >= 0")
	}
	if err := validModel(p.Model); err != nil {
		return err
	}
	if len(p.MessageRefs) == 0 {
		return fmt.Errorf("model_call_requested requires message_refs")
	}
	for _, ref := range p.MessageRefs {
		if !ValidMessageRef(ref) {
			return fmt.Errorf("invalid message ref %q", ref)
		}
	}
	if p.ToolSnapshotHash != "" && !IsSHA256Hash(p.ToolSnapshotHash) {
		return fmt.Errorf("malformed tool_snapshot_hash")
	}
	return nil
}

func (p *ModelCallCompleted) validate() error {
	if p.CallIndex < 0 {
		return fmt.Errorf("call_index must be >= 0")
	}
	if p.Message.Role != RoleAssistant {
		return fmt.Errorf("model_call_completed message role must be %q", RoleAssistant)
	}
	if err := validMessage(p.Message); err != nil {
		return err
	}
	switch p.StopReason {
	case StopEndTurn, StopToolCalls, StopLength, StopContentFilter:
	default:
		return fmt.Errorf("unknown stop_reason %q", p.StopReason)
	}
	if p.Usage.InputTokens < 0 || p.Usage.OutputTokens < 0 {
		return fmt.Errorf("usage must be non-negative")
	}
	if p.ProviderDataHash != "" && !IsSHA256Hash(p.ProviderDataHash) {
		return fmt.Errorf("malformed provider_data_hash")
	}
	return nil
}

func (p *ModelCallFailed) validate() error {
	if p.CallIndex < 0 {
		return fmt.Errorf("call_index must be >= 0")
	}
	switch p.Class {
	case FailProvider, FailInterrupted, FailTimeout, FailInvalidResponse:
	default:
		return fmt.Errorf("unknown failure class %q", p.Class)
	}
	if p.Message == "" {
		return fmt.Errorf("model_call_failed requires a message")
	}
	return nil
}

func (p *ToolPermissionRequired) validate() error {
	if err := validToolCallID(p.ToolCallID); err != nil {
		return err
	}
	if p.ToolID == "" {
		return fmt.Errorf("tool_permission_required requires tool_id")
	}
	switch p.Requirement {
	case "kernel-verdict", "command-allowlist", "file-boundary", "human-approval":
	default:
		return fmt.Errorf("unknown requirement %q", p.Requirement)
	}
	return nil
}

func (p *ToolPermissionResolved) validate() error {
	if err := validToolCallID(p.ToolCallID); err != nil {
		return err
	}
	switch p.Decision {
	case DecisionAllow, DecisionDeny:
	default:
		return fmt.Errorf("unknown decision %q", p.Decision)
	}
	if p.DecidedBy == "" {
		return fmt.Errorf("tool_permission_resolved requires decided_by")
	}
	return nil
}

func (p *ToolInvocationRequested) validate() error {
	if err := validToolCallID(p.ToolCallID); err != nil {
		return err
	}
	if p.ToolID == "" {
		return fmt.Errorf("tool_invocation_requested requires tool_id")
	}
	if len(p.Args) == 0 || !json.Valid(p.Args) {
		return fmt.Errorf("tool_invocation_requested has invalid args")
	}
	if !IsSHA256Hash(p.ArgsHash) {
		return fmt.Errorf("malformed args_hash")
	}
	want, err := ComputeArgsHash(p.Args)
	if err != nil {
		return err
	}
	if p.ArgsHash != want {
		return fmt.Errorf("args_hash does not match canonical args")
	}
	switch p.Mode {
	case ModeSync, ModeAsync:
	default:
		return fmt.Errorf("unknown mode %q", p.Mode)
	}
	return nil
}

func (p *ToolResult) validate() error {
	if err := validToolCallID(p.ToolCallID); err != nil {
		return err
	}
	switch p.Status {
	case ResultOK, ResultError:
	case ResultIndeterminate:
		if p.Content == "" {
			return fmt.Errorf("indeterminate result requires an explanatory content")
		}
	default:
		return fmt.Errorf("unknown result status %q", p.Status)
	}
	return nil
}

func (p *ToolsExtended) validate() error {
	if len(p.Tools) == 0 {
		return fmt.Errorf("tools_extended requires at least one tool")
	}
	if err := validToolDescriptors(p.Tools); err != nil {
		return err
	}
	if p.FirstAffectedModelCallIndex < 0 {
		return fmt.Errorf("first_affected_model_call_index must be >= 0")
	}
	if p.Source == "" {
		return fmt.Errorf("tools_extended requires a source")
	}
	return nil
}

func (p *TurnSuspended) validate() error {
	if p.Reason == "" {
		return fmt.Errorf("turn_suspended requires a reason")
	}
	for _, id := range append(append([]string{}, p.PendingAsyncToolCallIDs...), p.OutstandingPermissionToolCallIDs...) {
		if err := validToolCallID(id); err != nil {
			return err
		}
	}
	return nil
}

func (p *TurnResumed) validate() error {
	if p.Reason == "" {
		return fmt.Errorf("turn_resumed requires a reason")
	}
	return nil
}

func (p *TurnCompleted) validate() error {
	if p.Outcome == "" {
		return fmt.Errorf("turn_completed requires an outcome")
	}
	if p.Usage.InputTokens < 0 || p.Usage.OutputTokens < 0 {
		return fmt.Errorf("usage must be non-negative")
	}
	return nil
}

func (p *TurnFailed) validate() error {
	if p.Class == "" || p.Message == "" {
		return fmt.Errorf("turn_failed requires class and message")
	}
	return nil
}

func (p *TurnCancelled) validate() error {
	if p.Reason == "" {
		return fmt.Errorf("turn_cancelled requires a reason")
	}
	return nil
}
