package mcpserver

// quantum_posture: the tests compare strings and lengths; nothing here signs or
// verifies, and no post-quantum claim is made.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// declared is an adapter that only declares.
type declared []adapters.Declaration

func (d declared) Declarations() []adapters.Declaration { return d }
func (declared) Prepare(context.Context, adapters.TokenSource, adapters.Effect) (*adapters.Preparation, error) {
	return nil, errors.New("not used")
}
func (declared) Dispatch(context.Context, adapters.TokenSource, adapters.Effect, []byte) adapters.DispatchResult {
	return adapters.DispatchResult{}
}
func (declared) Observe(context.Context, adapters.TokenSource, adapters.Effect) adapters.ObserveResult {
	return adapters.ObserveResult{}
}

func schemaOf(body string) []byte { return []byte(body) }

func TestEffectToolsAreTheGrantableEffectsThatCarryASchema(t *testing.T) {
	tools, err := effectTools([]adapters.Adapter{github.New(), declared{
		// Not grantable: the gateway's own authority effects.
		{EffectType: "helm.authority.provision.v1", ArgumentSchema: schemaOf(`{"type":"object"}`)},
		// No schema: a client could not say what to send.
		{EffectType: "ops.note", Grantable: true},
		// A model call is made by the model endpoints, never proposed as a tool.
		{EffectType: effectargs.ModelInference, Grantable: true, ArgumentSchema: schemaOf(`{"type":"object"}`)},
		{EffectType: "helm.work.report", Grantable: true, TargetForm: "work:{work_item_id}", Description: "Report the outcome.",
			ArgumentSchema: schemaOf(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://x/y","x-helm":{"a":1},"type":"object","additionalProperties":false}`)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for name := range tools {
		names = append(names, name)
	}
	want := []string{"github_branch_create_from_changes", "github_pull_request_create_draft", "github_repository_get", "helm_work_report"}
	if len(names) != len(want) {
		t.Fatalf("tools = %v, want %v", names, want)
	}
	for _, name := range want {
		if tools[name].Name != name || tools[name].effectType == "" {
			t.Fatalf("tool %s = %+v", name, tools[name])
		}
	}
	if tools["github_repository_get"].effectType != "github.repository.get" {
		t.Fatalf("effect type = %s", tools["github_repository_get"].effectType)
	}

	// The input names the target apart from the arguments, and the arguments
	// keep their closed schema without the keywords of a document root.
	var input struct {
		Type       string   `json:"type"`
		Additional bool     `json:"additionalProperties"`
		Required   []string `json:"required"`
		Properties struct {
			Target    map[string]any `json:"target"`
			Arguments map[string]any `json:"arguments"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(tools["helm_work_report"].InputSchema, &input); err != nil {
		t.Fatal(err)
	}
	if input.Type != "object" || input.Additional || !reflect.DeepEqual(input.Required, []string{"target", "arguments"}) ||
		input.Properties.Target["type"] != "string" || !strings.Contains(input.Properties.Target["description"].(string), "work:{work_item_id}") {
		t.Fatalf("input = %+v", input)
	}
	if !reflect.DeepEqual(input.Properties.Arguments, map[string]any{"type": "object", "additionalProperties": false}) {
		t.Fatalf("arguments schema = %v", input.Properties.Arguments)
	}
	if d := tools["helm_work_report"].Description; d != "Report the outcome. Target: work:{work_item_id}." {
		t.Fatalf("description = %q", d)
	}

	// The schema of a kernel effect is the published one, less the same three
	// keywords.
	published, ok := effectargs.ArgumentSchema(effectargs.GitHubRepositoryGet)
	if !ok {
		t.Fatal("no published schema")
	}
	var full map[string]any
	if err := json.Unmarshal(published, &full); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"$schema", "$id", "x-helm"} {
		delete(full, key)
	}
	var repo struct {
		Properties struct {
			Arguments map[string]any `json:"arguments"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(tools["github_repository_get"].InputSchema, &repo); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(repo.Properties.Arguments, full) {
		t.Fatalf("github_repository_get arguments schema differs from the published one:\n got %v\nwant %v", repo.Properties.Arguments, full)
	}
	// The real tools all pass the client-side rule for a tool name.
	for name := range tools {
		if !toolNamePattern.MatchString(name) {
			t.Errorf("%q is not a tool name", name)
		}
	}
}

func TestEffectToolsRefuseWhatCannotBeNamedOrIsNamedTwice(t *testing.T) {
	schema := schemaOf(`{"type":"object"}`)
	long := "a." + strings.Repeat("b", 70)
	for name, test := range map[string]declared{
		"a name past 64 characters": {{EffectType: long, Grantable: true, ArgumentSchema: schema}},
		"two effect types that collapse to one name": {
			{EffectType: "a.b_c", Grantable: true, ArgumentSchema: schema}, {EffectType: "a_b.c", Grantable: true, ArgumentSchema: schema}},
		"an effect type named like the attempt tool": {{EffectType: "helm.attempt.get", Grantable: true, ArgumentSchema: schema}},
		"a schema that is not JSON":                  {{EffectType: "ops.note", Grantable: true, ArgumentSchema: schemaOf(`{`)}},
		"a schema that is not an object":             {{EffectType: "ops.note", Grantable: true, ArgumentSchema: schemaOf(`[1]`)}},
	} {
		if _, err := effectTools([]adapters.Adapter{test}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if toolName("github.pull_request.create_draft") != "github_pull_request_create_draft" || toolName("ops-note") != "ops-note" {
		t.Fatal("a dot is not the only thing toolName changes")
	}
}

func TestEveryAttemptStateHasItsResult(t *testing.T) {
	succeeded := admission.Attempt{ID: "a", EffectType: "github.pull_request.create_draft", Target: "github.com/o/r", State: "OBSERVED", Outcome: "SUCCEEDED",
		LatestObservation: &admission.Observation{GitHubPullRequest: &adapters.GitHubPullRequestResult{Number: 7, URL: "https://github.com/o/r/pull/7"}}}
	for name, test := range map[string]struct {
		attempt admission.Attempt
		status  string
		isError bool
		reason  string
	}{
		"observed and succeeded":   {succeeded, "succeeded", false, ""},
		"reconciled and succeeded": {admission.Attempt{ID: "a", State: "RECONCILED", Outcome: "SUCCEEDED"}, "succeeded", false, ""},
		"settled":                  {admission.Attempt{ID: "a", State: "SETTLED", Outcome: "SUCCEEDED"}, "succeeded", false, ""},
		"observed and failed":      {admission.Attempt{ID: "a", State: "OBSERVED", Outcome: "FAILED", ReasonCode: string(contracts.ReasonPreconditionFailed)}, "failed", true, "PRECONDITION_FAILED"},
		"escalated":                {admission.Attempt{ID: "a", State: "ESCALATED", ReasonCode: string(contracts.ReasonApprovalRequired)}, "escalated", false, "APPROVAL_REQUIRED"},
		"denied":                   {admission.Attempt{ID: "a", State: "DENIED", ReasonCode: string(contracts.ReasonEffectOutOfScope)}, "denied", true, "EFFECT_OUT_OF_SCOPE"},
		"rejected":                 {admission.Attempt{ID: "a", State: "REJECTED", ReasonCode: string(contracts.ReasonApprovalRejected)}, "rejected", true, "APPROVAL_REJECTED"},
		"expired":                  {admission.Attempt{ID: "a", State: "EXPIRED", ReasonCode: string(contracts.ReasonApprovalTimeout)}, "expired", true, "APPROVAL_TIMEOUT"},
		"cancelled":                {admission.Attempt{ID: "a", State: "CANCELLED", ReasonCode: string(contracts.ReasonEmergencyStopFenced)}, "cancelled", true, "EMERGENCY_STOP_FENCED"},
		"unknown":                  {admission.Attempt{ID: "a", State: "UNKNOWN"}, "reconciling", false, ""},
		"dispatching":              {admission.Attempt{ID: "a", State: "DISPATCHING"}, "reconciling", false, ""},
		"dispatched":               {admission.Attempt{ID: "a", State: "DISPATCHED"}, "reconciling", false, ""},
		"handed to a human":        {admission.Attempt{ID: "a", State: "ESCALATED_TO_HUMAN"}, "reconciling", false, ""},
		"admitted but not sent":    {admission.Attempt{ID: "a", State: "ADMITTED"}, "reconciling", false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			got := resultFor(test.attempt)
			if got.IsError != test.isError || got.StructuredContent["status"] != test.status || got.StructuredContent["attempt_id"] != "a" {
				t.Fatalf("result = %+v", got)
			}
			if test.reason != "" && got.StructuredContent["reason_code"] != test.reason {
				t.Fatalf("reason_code = %v, want %s", got.StructuredContent["reason_code"], test.reason)
			}
			if test.reason == "" && got.StructuredContent["reason_code"] != nil {
				t.Fatalf("reason_code = %v, want none", got.StructuredContent["reason_code"])
			}
			if _, err := json.Marshal(got.StructuredContent); err != nil {
				t.Fatalf("the result does not encode: %v", err)
			}
		})
	}
	got := resultFor(succeeded).StructuredContent
	if got["result_kind"] != "github_pull_request" || got["result"].(*adapters.GitHubPullRequestResult).Number != 7 || got["outcome"] != "SUCCEEDED" {
		t.Fatalf("typed result = %v", got)
	}
	if message := resultFor(admission.Attempt{State: "DENIED", ReasonCode: string(contracts.ReasonEffectOutOfScope)}).StructuredContent["message"]; message == nil || message == "" {
		t.Fatal("a denial says nothing a worker can act on")
	}
}

// fakeLedger scripts admission for the sequencing tests.
type fakeLedger struct {
	effects                                admission.PrincipalEffects
	grants                                 admission.Grants
	proposed                               []admission.ProposeInput
	propose                                func(n int, in admission.ProposeInput) (admission.Attempt, bool, error)
	dispatched, observed, read, grantsRead int
	dispatch, observe                      func(id string) (admission.Attempt, error)
	get                                    func(id string) (admission.Attempt, error)
	callers                                []admission.Caller
}

func (l *fakeLedger) PrincipalEffects(_ context.Context, c admission.Caller) (admission.PrincipalEffects, error) {
	l.callers = append(l.callers, c)
	return l.effects, nil
}

func (l *fakeLedger) ModelGrants(context.Context, admission.Caller, string) (admission.Grants, error) {
	l.grantsRead++
	return l.grants, nil
}

func (l *fakeLedger) ProposeWorkEffect(_ context.Context, _ admission.Caller, in admission.ProposeInput) (admission.Attempt, bool, error) {
	l.proposed = append(l.proposed, in)
	return l.propose(len(l.proposed)-1, in)
}

func (l *fakeLedger) Dispatch(_ context.Context, _ admission.Caller, id string) (admission.Attempt, bool, error) {
	l.dispatched++
	a, err := l.dispatch(id)
	return a, false, err
}

func (l *fakeLedger) Observe(_ context.Context, _ admission.Caller, id string) (admission.Attempt, bool, error) {
	l.observed++
	a, err := l.observe(id)
	return a, false, err
}

func (l *fakeLedger) Get(_ context.Context, _ admission.Caller, id string) (admission.Attempt, error) {
	l.read++
	return l.get(id)
}

func attemptIn(state, outcome string) admission.Attempt {
	return admission.Attempt{Episode: workerCaller().Episode, RequesterPrincipalID: "agt:seat", ID: "11111111-1111-7111-8111-111111111111", EffectType: "github.repository.get", Target: "github.com/o/r", State: state, Outcome: outcome}
}

func newGateway(t *testing.T, l *fakeLedger) *Gateway {
	t.Helper()
	g, err := NewGateway(l, []adapters.Adapter{github.New()})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

const repoCall = `{"target":"github.com/o/r","arguments":{"schema":"helm.github.repository.get.v1"}}`

func call(id string, args string) Call {
	return Call{RequestID: json.RawMessage(id), Name: "github_repository_get", Arguments: json.RawMessage(args)}
}

func TestToolsListTheEffectsOfTheCallersMandatesAndOnlyAgentsAsk(t *testing.T) {
	l := &fakeLedger{effects: admission.PrincipalEffects{Kind: "agent", Active: true,
		EffectTypes: []string{"github.repository.get", "ops.unregistered", "github.pull_request.create_draft"}}}
	g := newGateway(t, l)
	tools, err := g.Tools(context.Background(), workerCaller())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	// What the mandates name and the gateway performs, and the attempt tool;
	// an effect type the gateway does not perform is not a tool.
	if !reflect.DeepEqual(names, []string{AttemptGetTool, "github_repository_get", "github_pull_request_create_draft"}) {
		t.Fatalf("tools = %v", names)
	}
	if l.callers[0].Episode == nil || l.callers[0].PrincipalID != "agt:seat" {
		t.Fatalf("the ledger was asked about %+v", l.callers[0])
	}
	// A seat with no mandates has the attempt tool and nothing else.
	l.effects = admission.PrincipalEffects{Kind: "agent", Active: true}
	if tools, _ := g.Tools(context.Background(), workerCaller()); len(tools) != 1 || tools[0].Name != AttemptGetTool {
		t.Fatalf("tools without mandates = %v", tools)
	}
	// A human or a service, and a principal the tenant does not know, get nothing.
	for _, kind := range []string{"human", "service", ""} {
		l.effects = admission.PrincipalEffects{Kind: kind, Active: true, EffectTypes: []string{"github.repository.get"}}
		if _, err := g.Tools(context.Background(), workerCaller()); !errors.Is(err, ErrForbidden) {
			t.Errorf("kind %q listed tools: %v", kind, err)
		}
	}
	// A caller with no episode claim is not a worker at all.
	c := workerCaller()
	c.Episode = nil
	if _, err := g.Tools(context.Background(), c); !errors.Is(err, ErrForbidden) {
		t.Fatalf("a caller with no episode: %v", err)
	}
	// A refusal of the caller's own identity is a forbidden endpoint, and any
	// other ledger failure is the gateway's.
	l2 := &fakeLedger{}
	g2 := newGateway(t, l2)
	bad := &failingEffects{fakeLedger: l2, err: &admission.Error{Code: admission.CodePermissionDenied, Message: "no"}}
	g2.ledger = bad
	if _, err := g2.Tools(context.Background(), workerCaller()); !errors.Is(err, ErrForbidden) {
		t.Fatalf("a refused identity: %v", err)
	}
	bad.err = errors.New("connection refused")
	if _, err := g2.Tools(context.Background(), workerCaller()); err == nil || errors.Is(err, ErrForbidden) {
		t.Fatalf("a ledger failure: %v", err)
	}
}

type failingEffects struct {
	*fakeLedger
	err error
}

func (f *failingEffects) PrincipalEffects(context.Context, admission.Caller) (admission.PrincipalEffects, error) {
	return admission.PrincipalEffects{}, f.err
}

// An admitted call is dispatched and, when the dispatch leaves the outcome open,
// observed, in the one call, by the ledger call the worker's own caller makes.
func TestAdmittedCallsAreDispatchedAndObservedInTheSameCall(t *testing.T) {
	l := &fakeLedger{grants: admission.Grants{PrincipalKind: "agent", PrincipalActive: true, SumUnits: []string{"usd_micros"}}}
	l.propose = func(int, admission.ProposeInput) (admission.Attempt, bool, error) {
		return attemptIn("ADMITTED", ""), false, nil
	}
	l.dispatch = func(string) (admission.Attempt, error) { return attemptIn("OBSERVED", "SUCCEEDED"), nil }
	got, err := newGateway(t, l).Call(context.Background(), workerCaller(), call("1", repoCall))
	if err != nil || got.IsError || got.StructuredContent["status"] != "succeeded" {
		t.Fatalf("call = %+v, %v", got, err)
	}
	if l.dispatched != 1 || l.observed != 0 {
		t.Fatalf("dispatched %d, observed %d: a settled dispatch needs no read-back", l.dispatched, l.observed)
	}
	in := l.proposed[0]
	if in.EffectType != "github.repository.get" || in.Target != "github.com/o/r" ||
		in.IdempotencyKey != "" ||
		string(in.Arguments) != `{"schema":"helm.github.repository.get.v1"}` || in.CaseID != "" || in.CommitmentID != "" || in.MandateID != "" {
		t.Fatalf("proposal = %+v", in)
	}
	// The call prices itself at zero in every unit the chain sums.
	if !reflect.DeepEqual(in.Quote, []admission.Amount{{Unit: "usd_micros"}}) {
		t.Fatalf("quote = %v", in.Quote)
	}

	// A dispatch that leaves the effect open is read back once, and what is
	// still open after that is reconciling, not an error.
	l.dispatch = func(string) (admission.Attempt, error) { return attemptIn("DISPATCHED", ""), nil }
	l.observe = func(string) (admission.Attempt, error) { return attemptIn("UNKNOWN", ""), nil }
	got, _ = newGateway(t, l).Call(context.Background(), workerCaller(), call("2", repoCall))
	if got.IsError || got.StructuredContent["status"] != "reconciling" || l.observed != 1 {
		t.Fatalf("an open dispatch: %+v, observed %d", got, l.observed)
	}
	l.observe = func(string) (admission.Attempt, error) { return attemptIn("OBSERVED", "FAILED"), nil }
	l.observed = 0
	got, _ = newGateway(t, l).Call(context.Background(), workerCaller(), call("3", repoCall))
	if !got.IsError || got.StructuredContent["status"] != "failed" {
		t.Fatalf("a failed read-back: %+v", got)
	}
}

func TestEscalatedDeniedAndReplayedCallsAreNotDispatchedTwice(t *testing.T) {
	l := &fakeLedger{grants: admission.Grants{PrincipalKind: "agent"}}
	never := func(string) (admission.Attempt, error) {
		t.Fatal("the ledger was asked to send an attempt that is not admitted")
		return admission.Attempt{}, nil
	}
	l.dispatch, l.observe = never, never
	g := newGateway(t, l)
	for state, want := range map[string]string{"ESCALATED": "escalated", "DENIED": "denied", "OBSERVED": "succeeded", "REJECTED": "rejected", "CANCELLED": "cancelled"} {
		outcome := ""
		if state == "OBSERVED" {
			outcome = "SUCCEEDED"
		}
		l.propose = func(int, admission.ProposeInput) (admission.Attempt, bool, error) {
			return attemptIn(state, outcome), state == "OBSERVED", nil
		}
		got, err := g.Call(context.Background(), workerCaller(), call("1", repoCall))
		if err != nil || got.StructuredContent["status"] != want {
			t.Errorf("%s: %+v, %v", state, got, err)
		}
	}
	// A replayed call whose attempt was admitted and never sent is sent now; one
	// in flight elsewhere is only read back, never sent again.
	l.dispatch = func(string) (admission.Attempt, error) { return attemptIn("OBSERVED", "SUCCEEDED"), nil }
	l.propose = func(int, admission.ProposeInput) (admission.Attempt, bool, error) {
		return attemptIn("ADMITTED", ""), true, nil
	}
	if got, _ := g.Call(context.Background(), workerCaller(), call("1", repoCall)); got.StructuredContent["status"] != "succeeded" || l.dispatched != 1 {
		t.Fatalf("an admitted replay: %+v, dispatched %d", got, l.dispatched)
	}
	l.dispatched = 0
	l.propose = func(int, admission.ProposeInput) (admission.Attempt, bool, error) {
		return attemptIn("DISPATCHING", ""), true, nil
	}
	l.observe = func(string) (admission.Attempt, error) { return attemptIn("DISPATCHING", ""), nil }
	if got, _ := g.Call(context.Background(), workerCaller(), call("1", repoCall)); got.IsError || got.StructuredContent["status"] != "reconciling" || l.dispatched != 0 {
		t.Fatalf("an in-flight replay: %+v, dispatched %d", got, l.dispatched)
	}
}

func TestApprovedEscalationReplayDoesNotDispatchOrObserve(t *testing.T) {
	for _, state := range []string{"ADMITTED", "DISPATCHING", "UNKNOWN", "OBSERVED"} {
		t.Run(state, func(t *testing.T) {
			l := &fakeLedger{grants: admission.Grants{PrincipalKind: "agent"}}
			l.propose = func(int, admission.ProposeInput) (admission.Attempt, bool, error) {
				a := attemptIn(state, "SUCCEEDED")
				a.ApprovalDigest = make([]byte, 32)
				return a, true, nil
			}
			never := func(string) (admission.Attempt, error) {
				t.Fatal("a worker retry drove an escalation on the control plane resume path")
				return admission.Attempt{}, nil
			}
			l.dispatch, l.observe = never, never
			got, err := newGateway(t, l).Call(context.Background(), workerCaller(), call("1", repoCall))
			want := "reconciling"
			if state == "OBSERVED" {
				want = "succeeded"
			}
			if err != nil || got.IsError || got.StructuredContent["status"] != want ||
				got.StructuredContent["attempt_id"] == "" || l.dispatched != 0 || l.observed != 0 {
				t.Fatalf("approved replay = %+v, %v; dispatch %d, observe %d", got, err, l.dispatched, l.observed)
			}
		})
	}
}

func TestRefusalsAreAnswersAndFailuresAreRetried(t *testing.T) {
	refusal := func(code admission.Code, reason contracts.ReasonCode, message string) error {
		return &admission.Error{Code: code, Reason: reason, Message: message}
	}
	l := &fakeLedger{grants: admission.Grants{PrincipalKind: "agent"}}
	g := newGateway(t, l)
	for name, test := range map[string]struct {
		err    error
		status string
		reason string
	}{
		"a schema violation":   {refusal(admission.CodeInvalidArgument, contracts.ReasonSchemaViolation, "effect.arguments: bad"), "invalid", "SCHEMA_VIOLATION"},
		"a denied principal":   {refusal(admission.CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "no"), "denied", "INSUFFICIENT_PRIVILEGE"},
		"an idempotency clash": {refusal(admission.CodeAlreadyExists, contracts.ReasonIdempotencyConflict, "different request"), "conflict", "IDEMPOTENCY_CONFLICT"},
		"a precondition":       {refusal(admission.CodeFailedPrecondition, contracts.ReasonPreconditionFailed, "no branch"), "refused", "PRECONDITION_FAILED"},
	} {
		l.propose = func(int, admission.ProposeInput) (admission.Attempt, bool, error) {
			return admission.Attempt{}, false, test.err
		}
		got, err := g.Call(context.Background(), workerCaller(), call("1", repoCall))
		if err != nil || !got.IsError || got.StructuredContent["status"] != test.status || got.StructuredContent["reason_code"] != test.reason ||
			got.StructuredContent["message"] == "" {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
	// The ledger being down is not an answer: the transport says to repeat.
	l.propose = func(int, admission.ProposeInput) (admission.Attempt, bool, error) {
		return admission.Attempt{}, false, errors.New("connection refused")
	}
	if got, err := g.Call(context.Background(), workerCaller(), call("1", repoCall)); err == nil || got.StructuredContent != nil {
		t.Fatalf("a ledger failure was answered: %+v, %v", got, err)
	}
	// A failed dispatch after the attempt exists names the attempt, so the
	// worker can ask about it.
	l.propose = func(int, admission.ProposeInput) (admission.Attempt, bool, error) {
		return attemptIn("ADMITTED", ""), false, nil
	}
	l.dispatch = func(string) (admission.Attempt, error) {
		return admission.Attempt{}, refusal(admission.CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "not its workload")
	}
	got, _ := g.Call(context.Background(), workerCaller(), call("1", repoCall))
	if !got.IsError || got.StructuredContent["attempt_id"] != attemptIn("", "").ID {
		t.Fatalf("a refused dispatch = %+v", got)
	}
	// A sum limit added since the grants were read is priced in once.
	l.grantsRead = 0
	proposals := 0
	l.propose = func(_ int, in admission.ProposeInput) (admission.Attempt, bool, error) {
		if proposals++; proposals == 1 {
			return admission.Attempt{}, false, refusal(admission.CodeInvalidArgument, contracts.ReasonSchemaViolation, `a sum limit counts "usd_micros", and the quote carries no amount for it`)
		}
		if len(in.Quote) != 1 {
			t.Fatalf("the retry's quote = %v", in.Quote)
		}
		return attemptIn("ESCALATED", ""), false, nil
	}
	l.grants = admission.Grants{PrincipalKind: "agent", SumUnits: []string{"usd_micros"}}
	if got, _ := g.Call(context.Background(), workerCaller(), call("1", repoCall)); got.StructuredContent["status"] != "escalated" || l.grantsRead != 2 {
		t.Fatalf("a refreshed quote: %+v, grants read %d", got, l.grantsRead)
	}
}

func TestCallsAreHeldToTheirContract(t *testing.T) {
	l := &fakeLedger{grants: admission.Grants{PrincipalKind: "agent"}}
	l.propose = func(int, admission.ProposeInput) (admission.Attempt, bool, error) {
		t.Fatal("a call that breaks the contract reached admission")
		return admission.Attempt{}, false, nil
	}
	g := newGateway(t, l)
	ctx := context.Background()
	// An unknown tool is a protocol error.
	if _, err := g.Call(ctx, workerCaller(), Call{RequestID: json.RawMessage(`1`), Name: "github_nothing", Arguments: json.RawMessage(`{}`)}); !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("an unknown tool: %v", err)
	}
	// The effect is named by the tool and its target by the call, never by the
	// arguments' own fields, and a body cannot add fields.
	for name, args := range map[string]string{
		"no target":            `{"arguments":{"schema":"helm.github.repository.get.v1"}}`,
		"an empty target":      `{"target":"","arguments":{}}`,
		"no arguments":         `{"target":"github.com/o/r"}`,
		"arguments not object": `{"target":"github.com/o/r","arguments":[]}`,
		"a smuggled case":      `{"target":"github.com/o/r","arguments":{},"case_id":"other"}`,
		"a smuggled episode":   `{"target":"github.com/o/r","arguments":{},"episode_id":"other"}`,
		"a duplicated target":  `{"target":"github.com/o/r","target":"github.com/o/other","arguments":{}}`,
		"an empty object":      `{}`,
	} {
		got, err := g.Call(ctx, workerCaller(), call("1", args))
		if err != nil || !got.IsError || got.StructuredContent["status"] != "invalid" {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
	// A token that reads does not propose.
	c := workerCaller()
	c.Scope = "helm.gateway.read"
	got, err := g.Call(ctx, c, call("1", repoCall))
	if err != nil || !got.IsError || got.StructuredContent["status"] != "denied" || got.StructuredContent["reason_code"] != "INSUFFICIENT_PRIVILEGE" {
		t.Fatalf("a read token proposing: %+v, %v", got, err)
	}
	// A principal that is not an agent is forbidden, before anything is proposed.
	for _, kind := range []string{"human", "service", ""} {
		l.grants = admission.Grants{PrincipalKind: kind}
		if _, err := g.Call(ctx, workerCaller(), call("1", repoCall)); !errors.Is(err, ErrForbidden) {
			t.Errorf("kind %q proposed: %v", kind, err)
		}
	}
	// A caller that carries no episode is not a worker.
	c = workerCaller()
	c.Episode = nil
	if _, err := g.Call(ctx, c, call("1", repoCall)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("a caller with no episode: %v", err)
	}
}

func TestAttemptGetReadsThroughTheLedgersEpisodeScope(t *testing.T) {
	l := &fakeLedger{effects: admission.PrincipalEffects{Kind: "agent", Active: true}}
	g := newGateway(t, l)
	id := attemptIn("", "").ID
	l.get = func(got string) (admission.Attempt, error) {
		if got != id {
			return admission.Attempt{}, &admission.Error{Code: admission.CodeNotFound, Message: "no such attempt"}
		}
		return attemptIn("OBSERVED", "SUCCEEDED"), nil
	}
	read := func(args string, scope string) Result {
		c := workerCaller()
		c.Scope = scope
		r, err := g.Call(context.Background(), c, Call{RequestID: json.RawMessage(`1`), Name: AttemptGetTool, Arguments: json.RawMessage(args)})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// Either scope of a worker token reads.
	for _, scope := range []string{"helm.gateway.propose", "helm.gateway.read"} {
		if got := read(`{"attempt_id":"`+id+`"}`, scope); got.IsError || got.StructuredContent["status"] != "succeeded" {
			t.Fatalf("%s: %+v", scope, got)
		}
	}
	if got := read(`{"attempt_id":"22222222-2222-7222-8222-222222222222"}`, "helm.gateway.propose"); !got.IsError || got.StructuredContent["status"] != "not_found" {
		t.Fatalf("an unknown attempt: %+v", got)
	}
	for _, args := range []string{`{}`, `{"attempt_id":""}`, `{"attempt_id":"x","episode_id":"other"}`} {
		if got := read(args, "helm.gateway.propose"); !got.IsError || got.StructuredContent["status"] != "invalid" {
			t.Errorf("%s: %+v", args, got)
		}
	}
	l.effects = admission.PrincipalEffects{Kind: "human"}
	c := workerCaller()
	if _, err := g.Call(context.Background(), c, Call{RequestID: json.RawMessage(`1`), Name: AttemptGetTool, Arguments: json.RawMessage(`{"attempt_id":"` + id + `"}`)}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("a human reading: %v", err)
	}
}
