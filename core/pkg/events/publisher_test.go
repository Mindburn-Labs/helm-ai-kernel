package events

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type captureSlogHandler struct {
	record slog.Record
}

func (h *captureSlogHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureSlogHandler) Handle(_ context.Context, record slog.Record) error {
	h.record = record
	return nil
}
func (h *captureSlogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureSlogHandler) WithGroup(string) slog.Handler      { return h }

func TestSlogPublisherFlattensSyntheticLifecycleEvent(t *testing.T) {
	handler := &captureSlogHandler{}
	publish := SlogPublisher(slog.New(handler))
	event := NewRequestReceived(EventMeta{
		EventID:       "evt-1",
		CorrelationID: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		RunID:         StableRef("session"),
		TenantID:      StableRef("tenant"),
		SourceRef:     "MCP",
		Env:           EnvSynthetic,
	}, "EXECUTE_TOOL", "read", LifecycleEnrichment{Tool: "read"})

	if err := publish(context.Background(), event); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if handler.record.Message != "helm.lifecycle.event" {
		t.Fatalf("message = %q, want constant lifecycle message", handler.record.Message)
	}
	attrs := map[string]any{}
	var keys []string
	handler.record.Attrs(func(attr slog.Attr) bool {
		keys = append(keys, attr.Key)
		attrs[attr.Key] = attr.Value.Any()
		return true
	})
	wantKeys := []string{
		"helm.event.type",
		"helm.event.id",
		"helm.event.correlation_id",
		"helm.event.run_id",
		"helm.event.schema_version",
		"helm.event.env",
		"helm.event.tenant_id",
		"helm.event.source_ref",
		"helm.event.field.action",
		"helm.event.field.resource",
		"helm.event.field.tool",
	}
	if len(keys) != len(wantKeys) {
		t.Fatalf("attribute count = %d, want %d: %v", len(keys), len(wantKeys), keys)
	}
	for i, want := range wantKeys {
		if keys[i] != want {
			t.Errorf("attribute[%d] = %q, want %q", i, keys[i], want)
		}
	}
	for key, want := range map[string]any{
		"helm.event.type":           RequestReceived,
		"helm.event.id":             "evt-1",
		"helm.event.correlation_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		"helm.event.tenant_id":      StableRef("tenant"),
		"helm.event.source_ref":     "MCP",
		"helm.event.env":            EnvSynthetic,
		"helm.event.field.tool":     "read",
	} {
		if got := attrs[key]; got != want {
			t.Errorf("attr %q = %v, want %v", key, got, want)
		}
	}
	if _, nested := attrs["helm.event"]; nested {
		t.Fatal("publisher emitted a nested event object")
	}
}

func TestSlogPublisherRejectsNonSyntheticAndUnsafeFields(t *testing.T) {
	base := EventMeta{
		EventID:       "evt-1",
		CorrelationID: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		Env:           EnvSynthetic,
	}
	for name, event := range map[string]LifecycleEvent{
		"pilot":   NewRequestReceived(EventMeta{EventID: base.EventID, CorrelationID: base.CorrelationID, Env: EnvPilot}, "EXECUTE_TOOL", "read"),
		"hosted":  NewRequestReceived(EventMeta{EventID: base.EventID, CorrelationID: base.CorrelationID, Env: EnvCustomerHosted}, "EXECUTE_TOOL", "read"),
		"payload": NewRequestReceived(base, "EXECUTE_TOOL", "read"),
	} {
		if name == "payload" {
			event.Fields["payload"] = "customer payload"
		}
		err := SlogPublisher(slog.New(slog.NewTextHandler(nil, nil)))(context.Background(), event)
		if err == nil {
			t.Errorf("%s event was accepted", name)
		}
		if name == "payload" && !errors.Is(err, ErrUnsafeEventField) {
			t.Errorf("payload error = %v, want ErrUnsafeEventField", err)
		}
	}
}

func TestSlogPublisherRejectsUnknownTypeAndInvalidCorrelation(t *testing.T) {
	event := LifecycleEvent{Meta: EventMeta{
		EventID:       "evt-1",
		EventType:     "helm.unknown.v1",
		CorrelationID: "not-a-uuid",
		Env:           EnvSynthetic,
	}}
	err := SlogPublisher(slog.New(slog.NewTextHandler(nil, nil)))(context.Background(), event)
	if !errors.Is(err, ErrInvalidLifecycleEvent) {
		t.Fatalf("error = %v, want ErrInvalidLifecycleEvent", err)
	}

	event = NewRequestReceived(EventMeta{
		EventID:       "evt-1",
		CorrelationID: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		RunID:         "sha256:" + strings.Repeat("z", 64),
		TenantID:      "raw-tenant",
		Env:           EnvSynthetic,
	}, "EXECUTE_TOOL", "read")
	if err := SlogPublisher(slog.New(slog.NewTextHandler(nil, nil)))(context.Background(), event); !errors.Is(err, ErrInvalidLifecycleEvent) {
		t.Fatalf("error = %v, want ErrInvalidLifecycleEvent for unsafe identity metadata", err)
	}
}

func TestSlogPublisherDoesNotSerializeProhibitedValues(t *testing.T) {
	// This is a regression guard for the rejection boundary, not a fixture for
	// the runtime path.
	event := NewRequestFailed(EventMeta{
		EventID:       "evt-1",
		CorrelationID: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		Env:           EnvSynthetic,
	}, "POLICY_VIOLATION", 0)
	event.Fields["response"] = "raw response"
	encoded, _ := json.Marshal(event)
	if !strings.Contains(string(encoded), "raw response") {
		t.Fatal("test event did not contain prohibited value")
	}
	if err := SlogPublisher(slog.New(slog.NewTextHandler(nil, nil)))(context.Background(), event); !errors.Is(err, ErrUnsafeEventField) {
		t.Fatalf("error = %v, want ErrUnsafeEventField", err)
	}
}
