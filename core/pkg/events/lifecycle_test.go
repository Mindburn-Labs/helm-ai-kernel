package events

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func testMeta(correlationID string) EventMeta {
	return EventMeta{
		EventID:       "evt_1",
		TenantID:      "tenant_1",
		TimestampMs:   1754251200000,
		CorrelationID: correlationID,
		TraceID:       "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:        "00f067aa0ba902b7",
		Env:           EnvSynthetic,
	}
}

// TestEventMetaV2CarriesIdentity covers the envelope half of §4. Without these
// fields an event can be read but not joined: correlation_id is what turns a
// pile of events into one request's story, and trace_id/span_id are what link
// that story to the trace.
func TestEventMetaV2CarriesIdentity(t *testing.T) {
	meta := testMeta("3f2504e0-4f89-41d3-9a0c-0305e82c3301")
	meta.EventType = RequestReceived
	meta.RunID = "run_7"
	meta.SchemaVersion = EventSchemaVersion

	encoded, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for key, want := range map[string]any{
		"correlation_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		"run_id":         "run_7",
		"trace_id":       "4bf92f3577b34da6a3ce929d0e0e4736",
		"span_id":        "00f067aa0ba902b7",
		"env":            EnvSynthetic,
		"schema_version": float64(EventSchemaVersion),
	} {
		if got := decoded[key]; got != want {
			t.Errorf("meta[%q] = %v, want %v", key, got, want)
		}
	}
}

// The v1 fields are load-bearing for existing producers; v2 is additive only.
func TestEventMetaOmitsAbsentOptionalFields(t *testing.T) {
	encoded, err := json.Marshal(EventMeta{
		EventID:     "evt_1",
		EventType:   RequestReceived,
		TenantID:    "tenant_1",
		TimestampMs: 1754251200000,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{"correlation_id", "run_id", "trace_id", "span_id", "env", "source_ref"} {
		if _, present := decoded[key]; present {
			t.Errorf("optional field %q emitted when unset; v2 must be additive and omitempty", key)
		}
	}
	for _, key := range []string{"event_id", "event_type", "tenant_id", "timestamp_ms"} {
		if _, present := decoded[key]; !present {
			t.Errorf("required v1 field %q missing", key)
		}
	}
}

// TestLifecycleCatalogRegistersEightTypes pins §5. A missing type is a hole in
// the request story that only shows up when an operator queries for it.
func TestLifecycleCatalogRegistersEightTypes(t *testing.T) {
	want := []string{
		"helm.request.received.v1",
		"helm.request.classified.v1",
		"helm.policy.applied.v1",
		"helm.decision.made.v1",
		"helm.escalation.triggered.v1",
		"helm.dispatch.completed.v1",
		"helm.request.failed.v1",
		"helm.request.completed.v1",
	}

	got := LifecycleEventTypes()
	if len(got) != len(want) {
		t.Fatalf("catalog has %d lifecycle types, want %d: %v", len(got), len(want), got)
	}

	registered := make(map[string]bool, len(got))
	for _, eventType := range got {
		registered[eventType] = true
	}
	for _, eventType := range want {
		if !registered[eventType] {
			t.Errorf("lifecycle type %q not registered", eventType)
		}
	}
}

// TestDecisionMadeProjectsFromDecisionRecord: #4 must be a projection of the
// signed decision, not a parallel record. If it invented its own verdict the
// event stream could disagree with the receipt it is supposed to explain.
func TestDecisionMadeProjectsFromDecisionRecord(t *testing.T) {
	decision := contracts.DecisionRecord{
		ID:                 "dec_1",
		CorrelationID:      "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		SubjectID:          "did:helm:operator:ops",
		Action:             "payments.refund",
		Resource:           "orders/42",
		Verdict:            string(contracts.VerdictDeny),
		Reason:             "over limit",
		ReasonCode:         "SPEND_LIMIT_EXCEEDED",
		PolicyVersion:      "v3",
		PolicyContentHash:  "sha256:policy",
		PolicyEpoch:        "epoch_9",
		PolicyDecisionHash: "sha256:decision",
	}

	event := NewDecisionMade(testMeta(decision.CorrelationID), decision)

	if event.Meta.EventType != DecisionMade {
		t.Errorf("event_type = %q, want %q", event.Meta.EventType, DecisionMade)
	}
	for key, want := range map[string]any{
		"decision_id": "dec_1",
		"verdict":     "DENY",
		"reason_code": "SPEND_LIMIT_EXCEEDED",
		"action":      "payments.refund",
		"resource":    "orders/42",
	} {
		if got := event.Fields[key]; got != want {
			t.Errorf("fields[%q] = %v, want %v", key, got, want)
		}
	}
}

// #3 is a projection of the policy identity already bound into the decision,
// plus the rules the evidence recorded as fired.
func TestPolicyAppliedProjectsPolicyIdentity(t *testing.T) {
	decision := contracts.DecisionRecord{
		ID:                "dec_1",
		CorrelationID:     "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		PolicyVersion:     "v3",
		PolicyContentHash: "sha256:policy",
		PolicyEpoch:       "epoch_9",
	}

	event := NewPolicyApplied(testMeta(decision.CorrelationID), decision, []string{"rule.spend.cap", "rule.egress"})

	if event.Meta.EventType != PolicyApplied {
		t.Errorf("event_type = %q, want %q", event.Meta.EventType, PolicyApplied)
	}
	if got := event.Fields["policy_content_hash"]; got != "sha256:policy" {
		t.Errorf("policy_content_hash = %v, want the decision's bound hash", got)
	}
	rules, ok := event.Fields["rules_fired"].([]string)
	if !ok || len(rules) != 2 {
		t.Errorf("rules_fired = %v, want the two fired rules", event.Fields["rules_fired"])
	}
}

// #8 carries the cost of the request. TokensIn/TokensOut are the anchor the
// spec names; summing them here is what makes a per-request cost query
// possible without reading every PAL receipt.
func TestRequestCompletedProjectsExecutionAndTokens(t *testing.T) {
	execution := contracts.EvidencePackExecution{
		ExecutionID: "exec_1",
		Status:      "success",
		RetryCount:  1,
		DurationMs:  1234,
	}
	receipts := []contracts.PALReceiptRef{
		{ReceiptID: "pal_1", TokensIn: 100, TokensOut: 20, CompletedAt: time.Unix(0, 0)},
		{ReceiptID: "pal_2", TokensIn: 5, TokensOut: 3, CompletedAt: time.Unix(0, 0)},
	}

	event := NewRequestCompleted(testMeta("3f2504e0-4f89-41d3-9a0c-0305e82c3301"), execution, receipts)

	if event.Meta.EventType != RequestCompleted {
		t.Errorf("event_type = %q, want %q", event.Meta.EventType, RequestCompleted)
	}
	if got := event.Fields["tokens_in"]; got != 105 {
		t.Errorf("tokens_in = %v, want 105 (summed across PAL receipts)", got)
	}
	if got := event.Fields["tokens_out"]; got != 23 {
		t.Errorf("tokens_out = %v, want 23", got)
	}
	if got := event.Fields["status"]; got != "success" {
		t.Errorf("status = %v, want the execution status", got)
	}
}

// TestCompletenessInvariant is §5.1 and the reason the catalog is worth having:
// a request that never closed must be detectable. Silent loss is the failure
// mode an event stream is supposed to rule out.
func TestCompletenessInvariant(t *testing.T) {
	const correlationID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	received := LifecycleEvent{Meta: EventMeta{EventType: RequestReceived, CorrelationID: correlationID}}
	completed := LifecycleEvent{Meta: EventMeta{EventType: RequestCompleted, CorrelationID: correlationID}}
	failed := LifecycleEvent{Meta: EventMeta{EventType: RequestFailed, CorrelationID: correlationID}}
	decided := LifecycleEvent{Meta: EventMeta{EventType: DecisionMade, CorrelationID: correlationID}}

	tests := []struct {
		name    string
		events  []LifecycleEvent
		wantErr bool
	}{
		{"allow path closes with completed", []LifecycleEvent{received, decided, completed}, false},
		{"failure path closes with failed", []LifecycleEvent{received, decided, failed}, false},
		{"unclosed request is a signal, not silence", []LifecycleEvent{received, decided}, true},
		{"two terminal events", []LifecycleEvent{received, completed, failed}, true},
		{"terminal without a received", []LifecycleEvent{completed}, true},
		{"empty sequence", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRequestSequence(tt.events)
			if tt.wantErr && err == nil {
				t.Error("ValidateRequestSequence accepted an invalid sequence")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateRequestSequence rejected a valid sequence: %v", err)
			}
		})
	}
}

// Every event of one request must join on correlation_id — the §11 check that
// was unrunnable until this issue.
func TestSequenceRejectsMixedCorrelationIDs(t *testing.T) {
	events := []LifecycleEvent{
		{Meta: EventMeta{EventType: RequestReceived, CorrelationID: "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}},
		{Meta: EventMeta{EventType: RequestCompleted, CorrelationID: "9c5b94b1-35ad-49bb-b118-8e8fc24abf80"}},
	}

	if err := ValidateRequestSequence(events); err == nil {
		t.Error("accepted a sequence spanning two correlation ids; the join would silently merge two requests")
	}
}

// TestSyntheticRequestSequences walks the five shapes a governed request can
// take, built with the real constructors rather than hand-written envelopes.
// This is the half of HELM-290 §11 that had no build owner and could not be
// run: every shape emits #1 plus exactly one terminal, and every event of one
// request joins on correlation_id.
func TestSyntheticRequestSequences(t *testing.T) {
	const correlationID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"

	base := func() EventMeta { return testMeta(correlationID) }
	decision := func(verdict contracts.Verdict) contracts.DecisionRecord {
		return contracts.DecisionRecord{
			ID:            "dec_1",
			CorrelationID: correlationID,
			Action:        "payments.refund",
			Resource:      "orders/42",
			Verdict:       string(verdict),
			PolicyVersion: "v3",
		}
	}
	execution := contracts.EvidencePackExecution{ExecutionID: "exec_1", Status: "success"}

	sequences := map[string][]LifecycleEvent{
		"ALLOW dispatched and completed": {
			NewRequestReceived(base(), "payments.refund", "orders/42"),
			NewRequestClassified(base(), "financial.write", "high"),
			NewPolicyApplied(base(), decision(contracts.VerdictAllow), []string{"rule.spend.cap"}),
			NewDecisionMade(base(), decision(contracts.VerdictAllow)),
			NewDispatchCompleted(base(), contracts.Receipt{ID: "rec_1", Status: "applied"}, "sha256:intent"),
			NewRequestCompleted(base(), execution, nil),
		},
		"DENY closes as failed": {
			NewRequestReceived(base(), "payments.refund", "orders/42"),
			NewRequestClassified(base(), "financial.write", "high"),
			NewPolicyApplied(base(), decision(contracts.VerdictDeny), []string{"rule.spend.cap"}),
			NewDecisionMade(base(), decision(contracts.VerdictDeny)),
			NewRequestFailed(base(), "over limit", "SPEND_LIMIT_EXCEEDED", 0),
		},
		"ESCALATE then approved and completed": {
			NewRequestReceived(base(), "payments.refund", "orders/42"),
			NewDecisionMade(base(), decision(contracts.VerdictEscalate)),
			NewEscalationTriggered(base(), decision(contracts.VerdictEscalate)),
			NewDispatchCompleted(base(), contracts.Receipt{ID: "rec_1", Status: "applied"}, "sha256:intent"),
			NewRequestCompleted(base(), execution, nil),
		},
		"execution failure": {
			NewRequestReceived(base(), "payments.refund", "orders/42"),
			NewDecisionMade(base(), decision(contracts.VerdictAllow)),
			NewRequestFailed(base(), "upstream timeout", "EXECUTION_FAILED", 2),
		},
		"read-only request completes without dispatch": {
			NewRequestReceived(base(), "receipts.list", "receipts"),
			NewRequestCompleted(base(), execution, nil),
		},
	}

	for name, sequence := range sequences {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRequestSequence(sequence); err != nil {
				t.Errorf("valid %s sequence rejected: %v", name, err)
			}
			for _, event := range sequence {
				if event.Meta.CorrelationID != correlationID {
					t.Errorf("event %s does not join on correlation_id", event.Meta.EventType)
				}
				if event.Meta.SchemaVersion != EventSchemaVersion {
					t.Errorf("event %s has schema_version %d, want %d",
						event.Meta.EventType, event.Meta.SchemaVersion, EventSchemaVersion)
				}
			}
		})
	}
}
