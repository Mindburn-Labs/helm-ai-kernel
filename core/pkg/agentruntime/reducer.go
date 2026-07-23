package agentruntime

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Status is the lifecycle state of a turn as folded from its log.
type Status string

const (
	StatusRunning   Status = "running"
	StatusSuspended Status = "suspended"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// State is the folded state of a turn log. It is produced only by Reduce
// and is never mutated in place: every Reduce returns a fresh State, so
// the reducer is a pure function of (previous state, event).
type State struct {
	TurnID string
	Status Status
	Events int // number of events folded (== seq of the next event)

	Created *TurnCreated

	ModelCallsRequested int
	ModelCallsCompleted int
	ModelCallOpen       bool
	OpenModelCallIndex  int

	// AssistantMessages maps model-call index -> durable assistant message.
	AssistantMessages map[int]Message
	// ToolMessages maps tool_call_id -> durable tool message for every
	// settled call (real results and synthetic denial results).
	ToolMessages map[string]Message
	// ToolResultMeta maps tool_call_id -> settled result record.
	ToolResultMeta map[string]ToolResult
	// OpenInvocations maps tool_call_id -> invocation without a result.
	OpenInvocations map[string]ToolInvocationRequested
	// OutstandingPermissions maps tool_call_id -> unresolved requirement.
	OutstandingPermissions map[string]ToolPermissionRequired
	// PermissionDecisions maps tool_call_id -> recorded decision.
	PermissionDecisions map[string]ToolPermissionResolved
	// KnownToolCallIDs maps tool_call_id -> index of the model call that
	// produced it. A tool call may only be acted on if the model asked.
	KnownToolCallIDs map[string]int

	// Extensions are durable mid-turn toolset extensions, in log order.
	Extensions []ToolsExtended

	TotalUsage Usage
}

// Terminal reports whether the turn is in a terminal state.
func (s *State) Terminal() bool {
	return s.Status == StatusCompleted || s.Status == StatusFailed || s.Status == StatusCancelled
}

// EffectiveTools returns the toolset visible to model call callIndex:
// the base snapshot plus every extension whose FirstAffectedModelCallIndex
// is <= callIndex. Historical calls reconstruct with historical toolsets.
func (s *State) EffectiveTools(callIndex int) []ToolDescriptor {
	out := make([]ToolDescriptor, 0, len(s.Created.Tools))
	out = append(out, s.Created.Tools...)
	for _, ext := range s.Extensions {
		if ext.FirstAffectedModelCallIndex <= callIndex {
			out = append(out, ext.Tools...)
		}
	}
	return out
}

func (s *State) toolDescriptor(toolID string, callIndex int) *ToolDescriptor {
	for i, t := range s.EffectiveTools(callIndex) {
		if t.ToolID == toolID {
			return &s.EffectiveTools(callIndex)[i]
		}
	}
	return nil
}

func (s *State) clone() *State {
	c := *s
	c.AssistantMessages = make(map[int]Message, len(s.AssistantMessages))
	for k, v := range s.AssistantMessages {
		c.AssistantMessages[k] = v
	}
	c.ToolMessages = make(map[string]Message, len(s.ToolMessages))
	for k, v := range s.ToolMessages {
		c.ToolMessages[k] = v
	}
	c.ToolResultMeta = make(map[string]ToolResult, len(s.ToolResultMeta))
	for k, v := range s.ToolResultMeta {
		c.ToolResultMeta[k] = v
	}
	c.OpenInvocations = make(map[string]ToolInvocationRequested, len(s.OpenInvocations))
	for k, v := range s.OpenInvocations {
		c.OpenInvocations[k] = v
	}
	c.OutstandingPermissions = make(map[string]ToolPermissionRequired, len(s.OutstandingPermissions))
	for k, v := range s.OutstandingPermissions {
		c.OutstandingPermissions[k] = v
	}
	c.PermissionDecisions = make(map[string]ToolPermissionResolved, len(s.PermissionDecisions))
	for k, v := range s.PermissionDecisions {
		c.PermissionDecisions[k] = v
	}
	c.KnownToolCallIDs = make(map[string]int, len(s.KnownToolCallIDs))
	for k, v := range s.KnownToolCallIDs {
		c.KnownToolCallIDs[k] = v
	}
	c.Extensions = append([]ToolsExtended(nil), s.Extensions...)
	return &c
}

// Reduce folds one event into prev and returns the next state. It is the
// sole definition of legal turn history: prev == nil requires turn_created
// at seq 0; every later event must match turn ID, carry the next seq, and
// be a legal transition. Nothing may follow a terminal event.
func Reduce(prev *State, ev Event) (*State, error) {
	if err := ev.Validate(); err != nil {
		return nil, fmt.Errorf("invalid event: %w", err)
	}
	if prev == nil {
		if ev.Type != EventTurnCreated {
			return nil, fmt.Errorf("first event must be turn_created, got %q", ev.Type)
		}
		if ev.Seq != 0 {
			return nil, fmt.Errorf("first event must have seq 0, got %d", ev.Seq)
		}
		s := &State{
			TurnID:                 ev.TurnID,
			Status:                 StatusRunning,
			Events:                 1,
			Created:                ev.Created,
			OpenModelCallIndex:     -1,
			AssistantMessages:      map[int]Message{},
			ToolMessages:           map[string]Message{},
			ToolResultMeta:         map[string]ToolResult{},
			OpenInvocations:        map[string]ToolInvocationRequested{},
			OutstandingPermissions: map[string]ToolPermissionRequired{},
			PermissionDecisions:    map[string]ToolPermissionResolved{},
			KnownToolCallIDs:       map[string]int{},
		}
		return s, nil
	}

	if prev.Terminal() {
		return nil, fmt.Errorf("turn is terminal (%s); no events may follow", prev.Status)
	}
	if ev.TurnID != prev.TurnID {
		return nil, fmt.Errorf("turn_id mismatch: log is %q, event is %q", prev.TurnID, ev.TurnID)
	}
	if ev.Seq != uint64(prev.Events) {
		return nil, fmt.Errorf("seq mismatch: expected %d, got %d", prev.Events, ev.Seq)
	}
	if ev.Type == EventTurnCreated {
		return nil, fmt.Errorf("turn_created may only appear at seq 0")
	}

	s := prev.clone()
	var err error
	switch ev.Type {
	case EventModelCallRequested:
		err = s.applyModelCallRequested(ev.CallRequested)
	case EventModelCallCompleted:
		err = s.applyModelCallCompleted(ev.CallCompleted)
	case EventModelCallFailed:
		err = s.applyModelCallFailed(ev.CallFailed)
	case EventToolPermissionRequired:
		err = s.applyToolPermissionRequired(ev.PermRequired)
	case EventToolPermissionResolved:
		err = s.applyToolPermissionResolved(ev.PermResolved)
	case EventToolInvocationRequested:
		err = s.applyToolInvocationRequested(ev.InvRequested)
	case EventToolResult:
		err = s.applyToolResult(ev.ToolResult)
	case EventToolsExtended:
		err = s.applyToolsExtended(ev.ToolsExtended)
	case EventTurnSuspended:
		err = s.applyTurnSuspended(ev.Suspended)
	case EventTurnResumed:
		err = s.applyTurnResumed(ev.Resumed)
	case EventTurnCompleted:
		err = s.applyTurnCompleted(ev.Completed)
	case EventTurnFailed:
		err = s.applyTurnFailed(ev.Failed)
	case EventTurnCancelled:
		err = s.applyTurnCancelled(ev.Cancelled)
	default:
		err = fmt.Errorf("unhandled event type %q", ev.Type)
	}
	if err != nil {
		return nil, err
	}
	s.Events++
	return s, nil
}

// ReduceEvents folds a whole log from scratch.
func ReduceEvents(events []Event) (*State, error) {
	var s *State
	for i := range events {
		var err error
		s, err = Reduce(s, events[i])
		if err != nil {
			return nil, fmt.Errorf("event %d (%s): %w", i, events[i].Type, err)
		}
	}
	return s, nil
}

// ValidateAppend is the append gate: it folds existing plus candidates and
// returns the resulting state, or an error and no state. Store.Append calls
// this before any byte is written; a candidate sequence that fails here can
// never become durable.
func ValidateAppend(existing []Event, candidates ...Event) (*State, error) {
	all := make([]Event, 0, len(existing)+len(candidates))
	all = append(all, existing...)
	all = append(all, candidates...)
	return ReduceEvents(all)
}

func (s *State) applyModelCallRequested(p *ModelCallRequested) error {
	if s.Status != StatusRunning {
		return fmt.Errorf("model calls require a running turn (status %s)", s.Status)
	}
	if s.ModelCallOpen {
		return fmt.Errorf("model call %d is still open", s.OpenModelCallIndex)
	}
	if p.CallIndex != s.ModelCallsRequested {
		return fmt.Errorf("call_index %d out of order: next is %d", p.CallIndex, s.ModelCallsRequested)
	}
	if s.ModelCallsRequested >= s.Created.MaxModelCalls {
		return fmt.Errorf("model-call budget exhausted (%d/%d)", s.ModelCallsRequested, s.Created.MaxModelCalls)
	}
	// No model call happens until every tool call the previous assistant
	// message produced is settled and every permission is decided.
	if len(s.OpenInvocations) > 0 {
		return fmt.Errorf("tool invocations still open: %s", strings.Join(sortedKeys(s.OpenInvocations), ","))
	}
	if len(s.OutstandingPermissions) > 0 {
		return fmt.Errorf("permissions still outstanding: %s", strings.Join(sortedKeys(s.OutstandingPermissions), ","))
	}
	for id := range s.KnownToolCallIDs {
		if _, settled := s.ToolResultMeta[id]; !settled {
			return fmt.Errorf("tool call %q has neither result nor open invocation", id)
		}
	}
	// Every reference must resolve against durable state at request time;
	// an unresolvable reference can never become durable.
	for _, ref := range p.MessageRefs {
		if _, err := s.ResolveRef(ref); err != nil {
			return fmt.Errorf("unresolvable message ref %q: %w", ref, err)
		}
	}
	s.ModelCallOpen = true
	s.OpenModelCallIndex = p.CallIndex
	s.ModelCallsRequested++
	return nil
}

func (s *State) applyModelCallCompleted(p *ModelCallCompleted) error {
	if !s.ModelCallOpen || p.CallIndex != s.OpenModelCallIndex {
		return fmt.Errorf("no open model call with index %d", p.CallIndex)
	}
	for _, tc := range p.Message.ToolCalls {
		if _, dup := s.KnownToolCallIDs[tc.ToolCallID]; dup {
			return fmt.Errorf("tool_call_id %q already used in this turn", tc.ToolCallID)
		}
	}
	s.ModelCallOpen = false
	s.OpenModelCallIndex = -1
	s.ModelCallsCompleted++
	s.AssistantMessages[p.CallIndex] = p.Message
	for _, tc := range p.Message.ToolCalls {
		s.KnownToolCallIDs[tc.ToolCallID] = p.CallIndex
	}
	s.TotalUsage.InputTokens += p.Usage.InputTokens
	s.TotalUsage.OutputTokens += p.Usage.OutputTokens
	return nil
}

func (s *State) applyModelCallFailed(p *ModelCallFailed) error {
	if !s.ModelCallOpen || p.CallIndex != s.OpenModelCallIndex {
		return fmt.Errorf("no open model call with index %d", p.CallIndex)
	}
	s.ModelCallOpen = false
	s.OpenModelCallIndex = -1
	return nil
}

// lastCallIndex is the index of the most recent requested model call; tool
// interactions always refer to the latest completed assistant message.
func (s *State) lastCallIndex() int {
	return s.ModelCallsRequested - 1
}

func (s *State) applyToolPermissionRequired(p *ToolPermissionRequired) error {
	if s.ModelCallOpen {
		return fmt.Errorf("model call %d is still open", s.OpenModelCallIndex)
	}
	callIdx, known := s.KnownToolCallIDs[p.ToolCallID]
	if !known {
		return fmt.Errorf("tool call %q was never requested by the model", p.ToolCallID)
	}
	if callIdx != s.lastCallIndex() {
		return fmt.Errorf("tool call %q belongs to stale model call %d", p.ToolCallID, callIdx)
	}
	if _, open := s.OpenInvocations[p.ToolCallID]; open {
		return fmt.Errorf("tool call %q already invoked", p.ToolCallID)
	}
	if _, settled := s.ToolResultMeta[p.ToolCallID]; settled {
		return fmt.Errorf("tool call %q already settled", p.ToolCallID)
	}
	if _, outstanding := s.OutstandingPermissions[p.ToolCallID]; outstanding {
		return fmt.Errorf("permission already outstanding for tool call %q", p.ToolCallID)
	}
	if _, decided := s.PermissionDecisions[p.ToolCallID]; decided {
		return fmt.Errorf("permission already decided for tool call %q", p.ToolCallID)
	}
	s.OutstandingPermissions[p.ToolCallID] = *p
	return nil
}

func (s *State) applyToolPermissionResolved(p *ToolPermissionResolved) error {
	if _, outstanding := s.OutstandingPermissions[p.ToolCallID]; !outstanding {
		return fmt.Errorf("no outstanding permission for tool call %q", p.ToolCallID)
	}
	delete(s.OutstandingPermissions, p.ToolCallID)
	s.PermissionDecisions[p.ToolCallID] = *p
	return nil
}

func (s *State) applyToolInvocationRequested(p *ToolInvocationRequested) error {
	if s.ModelCallOpen {
		return fmt.Errorf("model call %d is still open", s.OpenModelCallIndex)
	}
	callIdx, known := s.KnownToolCallIDs[p.ToolCallID]
	if !known {
		return fmt.Errorf("tool call %q was never requested by the model", p.ToolCallID)
	}
	if callIdx != s.lastCallIndex() {
		return fmt.Errorf("tool call %q belongs to stale model call %d", p.ToolCallID, callIdx)
	}
	if _, open := s.OpenInvocations[p.ToolCallID]; open {
		return fmt.Errorf("tool call %q already invoked", p.ToolCallID)
	}
	if _, settled := s.ToolResultMeta[p.ToolCallID]; settled {
		return fmt.Errorf("tool call %q already settled", p.ToolCallID)
	}
	if _, outstanding := s.OutstandingPermissions[p.ToolCallID]; outstanding {
		return fmt.Errorf("permission still outstanding for tool call %q", p.ToolCallID)
	}
	if dec, decided := s.PermissionDecisions[p.ToolCallID]; decided && dec.Decision == DecisionDeny {
		return fmt.Errorf("tool call %q was denied; a denied call is never invoked", p.ToolCallID)
	}
	// Fail-closed: a tool whose descriptor requires permission may only be
	// invoked after a durable allow decision.
	if desc := s.toolDescriptor(p.ToolID, callIdx); desc != nil && desc.RequiresPermission {
		dec, decided := s.PermissionDecisions[p.ToolCallID]
		if !decided || dec.Decision != DecisionAllow {
			return fmt.Errorf("tool %q requires permission; no durable allow decision for %q", p.ToolID, p.ToolCallID)
		}
	}
	s.OpenInvocations[p.ToolCallID] = *p
	return nil
}

func (s *State) applyToolResult(p *ToolResult) error {
	if _, open := s.OpenInvocations[p.ToolCallID]; open {
		delete(s.OpenInvocations, p.ToolCallID)
		s.ToolResultMeta[p.ToolCallID] = *p
		s.ToolMessages[p.ToolCallID] = Message{Role: RoleTool, ToolCallID: p.ToolCallID, Content: p.Content}
		return nil
	}
	// Synthetic result path: a denied call gets an error result without an
	// invocation. The denial, not execution, is what the result records.
	if dec, decided := s.PermissionDecisions[p.ToolCallID]; decided && dec.Decision == DecisionDeny {
		if _, settled := s.ToolResultMeta[p.ToolCallID]; settled {
			return fmt.Errorf("tool call %q already settled", p.ToolCallID)
		}
		if p.Status != ResultError {
			return fmt.Errorf("a denied tool call may only receive an error result")
		}
		s.ToolResultMeta[p.ToolCallID] = *p
		s.ToolMessages[p.ToolCallID] = Message{Role: RoleTool, ToolCallID: p.ToolCallID, Content: p.Content}
		return nil
	}
	return fmt.Errorf("no open invocation or denied permission for tool call %q", p.ToolCallID)
}

func (s *State) applyToolsExtended(p *ToolsExtended) error {
	// Extensions apply to future model calls only; history is immutable.
	if p.FirstAffectedModelCallIndex < s.ModelCallsRequested {
		return fmt.Errorf("first_affected_model_call_index %d would rewrite call history (already requested %d)",
			p.FirstAffectedModelCallIndex, s.ModelCallsRequested)
	}
	existing := map[string]bool{}
	for _, t := range s.Created.Tools {
		existing[t.ToolID] = true
	}
	for _, ext := range s.Extensions {
		for _, t := range ext.Tools {
			existing[t.ToolID] = true
		}
	}
	for _, t := range p.Tools {
		if existing[t.ToolID] {
			return fmt.Errorf("tool %q is already in the toolset", t.ToolID)
		}
	}
	s.Extensions = append(s.Extensions, *p)
	return nil
}

func (s *State) applyTurnSuspended(p *TurnSuspended) error {
	if s.Status != StatusRunning {
		return fmt.Errorf("only a running turn can suspend (status %s)", s.Status)
	}
	if s.ModelCallOpen {
		return fmt.Errorf("cannot suspend with model call %d open", s.OpenModelCallIndex)
	}
	for id, inv := range s.OpenInvocations {
		if inv.Mode == ModeSync {
			return fmt.Errorf("cannot suspend with sync invocation %q open; sync tools settle within an advance or are marked indeterminate by recovery", id)
		}
	}
	pendingAsync := s.pendingAsyncToolCallIDs()
	outstanding := sortedKeys(s.OutstandingPermissions)
	if len(pendingAsync) == 0 && len(outstanding) == 0 {
		return fmt.Errorf("nothing pending; suspension would be a lie about the log")
	}
	// The snapshot must equal the folded pending set exactly: a suspension
	// snapshot is the recovery contract, so drift is unrepresentable.
	if !equalStringSets(pendingAsync, p.PendingAsyncToolCallIDs) ||
		!equalStringSets(outstanding, p.OutstandingPermissionToolCallIDs) {
		return fmt.Errorf("suspension snapshot does not match pending state (async %v, permissions %v)", pendingAsync, outstanding)
	}
	s.Status = StatusSuspended
	return nil
}

func (s *State) applyTurnResumed(_ *TurnResumed) error {
	if s.Status != StatusSuspended {
		return fmt.Errorf("only a suspended turn can resume (status %s)", s.Status)
	}
	s.Status = StatusRunning
	return nil
}

func (s *State) applyTurnCompleted(p *TurnCompleted) error {
	if s.Status != StatusRunning {
		return fmt.Errorf("only a running turn can complete (status %s)", s.Status)
	}
	if s.ModelCallOpen {
		return fmt.Errorf("model call %d is still open", s.OpenModelCallIndex)
	}
	if s.ModelCallsCompleted == 0 {
		return fmt.Errorf("turn has no completed model call")
	}
	if len(s.OpenInvocations) > 0 || len(s.OutstandingPermissions) > 0 {
		return fmt.Errorf("turn has open work")
	}
	for id := range s.KnownToolCallIDs {
		if _, settled := s.ToolResultMeta[id]; !settled {
			return fmt.Errorf("tool call %q is unsettled", id)
		}
	}
	s.TotalUsage.InputTokens += p.Usage.InputTokens
	s.TotalUsage.OutputTokens += p.Usage.OutputTokens
	s.Status = StatusCompleted
	return nil
}

func (s *State) applyTurnFailed(_ *TurnFailed) error {
	s.Status = StatusFailed
	return nil
}

func (s *State) applyTurnCancelled(_ *TurnCancelled) error {
	// Cancellation is legal from any non-terminal state and materializes
	// no live dependency (it never needs the model, tools, or context).
	s.Status = StatusCancelled
	return nil
}

// ResolveRef resolves one durable message reference against folded state.
func (s *State) ResolveRef(ref string) ([]Message, error) {
	switch {
	case ref == "input":
		return s.Created.Input, nil
	case strings.HasPrefix(ref, "assistant:"):
		n, err := strconv.Atoi(strings.TrimPrefix(ref, "assistant:"))
		if err != nil {
			return nil, fmt.Errorf("bad assistant ref")
		}
		m, ok := s.AssistantMessages[n]
		if !ok {
			return nil, fmt.Errorf("assistant message %d is not durable", n)
		}
		return []Message{m}, nil
	case strings.HasPrefix(ref, "tool_result:"):
		id := strings.TrimPrefix(ref, "tool_result:")
		m, ok := s.ToolMessages[id]
		if !ok {
			return nil, fmt.Errorf("tool result %q is not settled", id)
		}
		return []Message{m}, nil
	default:
		return nil, fmt.Errorf("unknown ref form")
	}
}

func (s *State) pendingAsyncToolCallIDs() []string {
	var out []string
	for id, inv := range s.OpenInvocations {
		if inv.Mode == ModeAsync {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equalStringSets(a, b []string) bool {
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
