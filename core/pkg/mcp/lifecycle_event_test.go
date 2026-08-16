package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/correlation"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/events"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"go.opentelemetry.io/otel/trace"
)

type lifecycleCapture struct {
	events []events.LifecycleEvent
}

func (c *lifecycleCapture) publish(_ context.Context, event events.LifecycleEvent) error {
	c.events = append(c.events, event)
	return nil
}

type lifecycleEvaluator struct {
	decision *contracts.DecisionRecord
	err      error
	calls    *int
}

func (e lifecycleEvaluator) EvaluateDecision(context.Context, guardian.DecisionRequest) (*contracts.DecisionRecord, error) {
	if e.calls != nil {
		*e.calls = *e.calls + 1
	}
	return e.decision, e.err
}

func TestGovernanceFirewallWrapPublishesCompleteLifecycleSequences(t *testing.T) {
	traceID, err := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	if err != nil {
		t.Fatal(err)
	}
	spanID, err := trace.SpanIDFromHex("00f067aa0ba902b7")
	if err != nil {
		t.Fatal(err)
	}
	const correlationID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"

	tests := []struct {
		name         string
		verdict      string
		evaluatorErr error
		handlerErr   error
		catalog      *ToolCatalog
		arguments    map[string]any
		wantTerminal string
		wantFailure  string
		wantDispatch bool
		wantHandler  bool
		receipt      *contracts.Receipt
		tenantID     string
		respIsError  bool
		nilHandler   bool
		preflight    bool
		nilEvaluator bool
		delegation   bool
		reservedArg  bool
	}{
		{
			name:         "allow completes",
			verdict:      string(contracts.VerdictAllow),
			catalog:      readOnlyCatalog(t),
			arguments:    map[string]any{"path": "/tmp/input"},
			wantTerminal: events.RequestCompleted,
			wantHandler:  true,
			tenantID:     "trusted-tenant",
		},
		{
			name:         "allow dispatches only with authoritative receipt",
			verdict:      string(contracts.VerdictAllow),
			catalog:      readOnlyCatalog(t),
			wantTerminal: events.RequestCompleted,
			wantDispatch: true,
			wantHandler:  true,
			receipt: &contracts.Receipt{
				ReceiptID:  "receipt-v5",
				ID:         "legacy-receipt-id",
				Status:     "SUCCESS",
				ArgsHash:   "sha256:" + strings.Repeat("a", 64),
				EffectID:   "effect-1",
				EffectType: "GITHUB_READ",
				RetryCount: 2,
			},
		},
		{
			name:         "allow completes without catalog",
			verdict:      string(contracts.VerdictAllow),
			wantTerminal: events.RequestCompleted,
			wantHandler:  true,
		},
		{
			name:         "deny fails",
			verdict:      string(contracts.VerdictDeny),
			wantTerminal: events.RequestFailed,
			wantFailure:  "policy",
		},
		{
			name:         "escalate fails after escalation",
			verdict:      string(contracts.VerdictEscalate),
			wantTerminal: events.RequestFailed,
			wantFailure:  "escalation",
		},
		{
			name:         "evaluator failure closes",
			verdict:      string(contracts.VerdictAllow),
			evaluatorErr: errors.New("raw evaluator detail"),
			wantTerminal: events.RequestFailed,
			wantFailure:  "evaluator",
		},
		{
			name:         "handler failure closes",
			verdict:      string(contracts.VerdictAllow),
			handlerErr:   errors.New("raw handler detail"),
			wantTerminal: events.RequestFailed,
			wantFailure:  "handler",
			wantHandler:  true,
		},
		{
			name:         "handler response error",
			verdict:      string(contracts.VerdictAllow),
			catalog:      readOnlyCatalog(t),
			respIsError:  true,
			wantTerminal: events.RequestFailed,
			wantFailure:  "handler",
			wantHandler:  true,
		},
		{
			name:         "nil handler",
			verdict:      string(contracts.VerdictAllow),
			catalog:      readOnlyCatalog(t),
			nilHandler:   true,
			wantTerminal: events.RequestFailed,
			wantFailure:  "handler",
		},
		{
			name:         "audit failure closes",
			verdict:      string(contracts.VerdictAllow),
			catalog:      readOnlyCatalog(t),
			arguments:    map[string]any{"bad": make(chan int)},
			wantTerminal: events.RequestFailed,
			wantFailure:  "audit",
			wantHandler:  true,
		},
		{
			name:         "delegation scope rejection",
			verdict:      string(contracts.VerdictAllow),
			catalog:      readOnlyCatalog(t),
			delegation:   true,
			preflight:    true,
			wantTerminal: events.RequestFailed,
			wantFailure:  "preflight",
		},
		{
			name:         "reserved security argument rejection",
			verdict:      string(contracts.VerdictAllow),
			catalog:      readOnlyCatalog(t),
			reservedArg:  true,
			preflight:    true,
			wantTerminal: events.RequestFailed,
			wantFailure:  "preflight",
		},
		{
			name:         "missing evaluator rejection",
			catalog:      readOnlyCatalog(t),
			nilEvaluator: true,
			preflight:    true,
			wantTerminal: events.RequestFailed,
			wantFailure:  "preflight",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture := &lifecycleCapture{}
			decision := &contracts.DecisionRecord{
				ID:            "decision-1",
				Action:        "EXECUTE_TOOL",
				Resource:      "read",
				SubjectID:     "raw-principal",
				Verdict:       tt.verdict,
				ReasonCode:    string(contracts.ReasonApprovalRequired),
				PolicyVersion: "policy-v1",
			}
			evaluatorCalls := 0
			var evaluator PolicyEvaluator = lifecycleEvaluator{decision: decision, err: tt.evaluatorErr, calls: &evaluatorCalls}
			if tt.nilEvaluator {
				evaluator = nil
			}
			fw := NewGovernanceFirewall(evaluator, tt.catalog, WithLifecyclePublisher(capture.publish))
			called := false
			var handler ToolHandler
			if !tt.nilHandler {
				handler = func(ctx context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
					called = true
					if tt.handlerErr != nil {
						return ToolExecutionResponse{Content: "raw response payload"}, tt.handlerErr
					}
					response := ToolExecutionResponse{Content: "raw response payload", IsError: tt.respIsError}
					if tt.receipt != nil {
						response.ExecutionReceipt = tt.receipt
						response.DispatchState = "dispatched"
						response.ApprovalHash = "approval-secret"
						response.ApproverID = "approver-raw"
						response.DispatchAdmissionExpiry = time.UnixMilli(1_754_000_000_000).UTC()
					}
					return response, nil
				}
			}
			ctx := trace.ContextWithSpanContext(
				correlation.With(context.Background(), correlation.ID(correlationID)),
				trace.NewSpanContext(trace.SpanContextConfig{TraceID: traceID, SpanID: spanID}),
			)
			wantTenant := events.StableRef("synthetic:raw-session")
			if tt.tenantID != "" {
				ctx = auth.WithPrincipal(ctx, &auth.BasePrincipal{TenantID: tt.tenantID})
				wantTenant = events.StableRef(tt.tenantID)
			}
			req := ToolExecutionRequest{ToolName: "read", SessionID: "raw-session", Arguments: tt.arguments}
			if tt.delegation {
				req.DelegationAllowedTools = []string{"other"}
			}
			if tt.reservedArg {
				req.Arguments = map[string]any{guardian.ContextSessionID: "attacker-set-session"}
			}
			resp, runErr := fw.WrapToolHandler(handler)(ctx, req)

			if tt.handlerErr != nil {
				if !errors.Is(runErr, tt.handlerErr) {
					t.Fatalf("wrapper error = %v, want handler error", runErr)
				}
			} else if tt.nilHandler {
				if runErr == nil {
					t.Fatal("nil handler returned no error")
				}
			} else if runErr != nil {
				t.Fatalf("wrapper error = %v", runErr)
			}
			if called != tt.wantHandler {
				t.Fatalf("handler called = %v, want %v", called, tt.wantHandler)
			}
			if !resp.Evaluated {
				t.Fatal("response was not marked evaluated")
			}
			if tt.respIsError && !resp.IsError {
				t.Fatal("handler response error was not preserved")
			}
			if evaluatorCalls != boolCount(!tt.preflight) {
				t.Fatalf("evaluator calls = %d, want %d", evaluatorCalls, boolCount(!tt.preflight))
			}
			if err := events.ValidateRequestSequence(capture.events); err != nil {
				t.Fatalf("sequence invalid: %v", err)
			}
			if got := countEvent(capture.events, events.RequestReceived); got != 1 {
				t.Fatalf("received count = %d, want 1", got)
			}
			if got := countEvent(capture.events, events.RequestClassified); got != boolCount(!tt.preflight) {
				t.Fatalf("classified count = %d, want %d", got, boolCount(!tt.preflight))
			}
			if got := countTerminal(capture.events); got != 1 {
				t.Fatalf("terminal count = %d, want 1", got)
			}
			if got := capture.events[len(capture.events)-1].Meta.EventType; got != tt.wantTerminal {
				t.Fatalf("terminal = %q, want %q", got, tt.wantTerminal)
			}
			if tt.wantFailure != "" {
				if got := fieldString(capture.events, events.RequestFailed, "failure_class"); got != tt.wantFailure {
					t.Fatalf("failure class = %q, want %q", got, tt.wantFailure)
				}
			}
			if countEvent(capture.events, events.DispatchCompleted) != boolCount(tt.wantDispatch) {
				t.Fatalf("dispatch presence does not match want=%v", tt.wantDispatch)
			}
			if tt.wantDispatch {
				dispatch := firstEvent(capture.events, events.DispatchCompleted)
				if receiptID, _ := dispatch.Fields["receipt_id"].(string); receiptID != tt.receipt.ReceiptID {
					t.Fatalf("dispatch receipt_id = %q, want authoritative receipt id %q", receiptID, tt.receipt.ReceiptID)
				}
				for key, want := range map[string]any{
					"args_hash":          tt.receipt.ArgsHash,
					"intent_hash":        tt.receipt.ArgsHash,
					"effect_id":          tt.receipt.EffectID,
					"effect_type":        tt.receipt.EffectType,
					"retry_count":        tt.receipt.RetryCount,
					"approval_ref":       events.StableRef("approval-secret"),
					"approver_ref":       events.StableRef("approver-raw"),
					"approval_expiry_ms": int64(1_754_000_000_000),
				} {
					if got := dispatch.Fields[key]; got != want {
						t.Fatalf("dispatch %s = %v, want %v", key, got, want)
					}
				}
				encoded := string(mustJSON(t, dispatch))
				for _, prohibited := range []string{"approval-secret", "approver-raw", "legacy-receipt-id"} {
					if strings.Contains(encoded, prohibited) {
						t.Fatalf("dispatch exported prohibited value %q: %s", prohibited, encoded)
					}
				}
			}
			if tt.wantTerminal == events.RequestCompleted {
				completed := firstEvent(capture.events, events.RequestCompleted)
				if _, fabricated := completed.Fields["tokens_in"]; fabricated {
					t.Fatal("MCP completion projected EvidencePack token fields")
				}
				if completed.Fields["outcome"] != "success" {
					t.Fatalf("completion outcome = %v, want success", completed.Fields["outcome"])
				}
			}
			if !tt.preflight {
				classified := firstEvent(capture.events, events.RequestClassified)
				if classified.Fields["classification_source"] != "catalog_hint" {
					t.Fatalf("classification source = %v, want catalog_hint", classified.Fields["classification_source"])
				}
			}
			for _, event := range capture.events {
				if event.Meta.CorrelationID != correlationID || event.Meta.RunID != events.StableRef("raw-session") || event.Meta.TenantID != wantTenant || event.Meta.SourceRef != lifecycleSourceRef {
					t.Fatalf("event identity mismatch: %+v", event.Meta)
				}
				if event.Meta.EventType == events.DecisionMade {
					if _, ok := event.Fields["decision_latency_ms"]; !ok {
						t.Fatal("decision event omitted measured decision_latency_ms")
					}
				}
				if event.Meta.EventType == events.RequestFailed && event.Fields["outcome"] != "failed" {
					t.Fatalf("failed event outcome = %v, want failed", event.Fields["outcome"])
				}
				if event.Meta.TraceID != traceID.String() || event.Meta.SpanID != spanID.String() {
					t.Fatalf("trace identity mismatch: %+v", event.Meta)
				}
				encoded := string(mustJSON(t, event))
				for _, prohibited := range []string{"raw-session", "raw-principal", "raw response payload", "raw evaluator detail", "raw handler detail", "attacker-set-session"} {
					if strings.Contains(encoded, prohibited) {
						t.Fatalf("event exported prohibited value %q: %s", prohibited, encoded)
					}
				}
			}
		})
	}
}

func readOnlyCatalog(t *testing.T) *ToolCatalog {
	t.Helper()
	catalog := NewToolCatalog()
	if err := catalog.Register(context.Background(), ToolRef{
		Name:        "read",
		Annotations: &ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}); err != nil {
		t.Fatal(err)
	}
	return catalog
}

func countEvent(sequence []events.LifecycleEvent, eventType string) int {
	count := 0
	for _, event := range sequence {
		if event.Meta.EventType == eventType {
			count++
		}
	}
	return count
}

func countTerminal(sequence []events.LifecycleEvent) int {
	return countEvent(sequence, events.RequestFailed) + countEvent(sequence, events.RequestCompleted)
}

func fieldString(sequence []events.LifecycleEvent, eventType, key string) string {
	for _, event := range sequence {
		if event.Meta.EventType == eventType {
			value, _ := event.Fields[key].(string)
			return value
		}
	}
	return ""
}

func firstEvent(sequence []events.LifecycleEvent, eventType string) events.LifecycleEvent {
	for _, event := range sequence {
		if event.Meta.EventType == eventType {
			return event
		}
	}
	return events.LifecycleEvent{}
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
