package events

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/correlation"
)

// EnvProduction is the non-synthetic default data class used when a trusted
// runtime does not explicitly select another lifecycle environment.
const EnvProduction = "production"

// Publisher is the narrow runtime seam for lifecycle publication. A function
// keeps the default path on slog while allowing tests and local collectors to
// capture events without another interface or dependency.
type Publisher func(context.Context, LifecycleEvent) error

var (
	ErrUnsupportedEventDataClass = errors.New("lifecycle events must be synthetic")
	ErrUnsafeEventField          = errors.New("lifecycle event contains an unsafe field")
	ErrInvalidLifecycleEvent     = errors.New("invalid lifecycle event")
)

// SlogPublisher publishes the event as flat attributes. The message is a
// constant so the collector can move only that safe value into Body; event
// fields remain queryable as helm.event.field.<name> attributes.
func SlogPublisher(logger *slog.Logger) Publisher {
	return func(ctx context.Context, event LifecycleEvent) error {
		if err := validatePublishedEvent(event); err != nil {
			return err
		}
		resolvedLogger := logger
		if resolvedLogger == nil {
			resolvedLogger = slog.Default()
		}

		attrs := []slog.Attr{
			slog.String("helm.event.type", event.Meta.EventType),
			slog.String("helm.event.id", event.Meta.EventID),
			slog.String("helm.event.correlation_id", event.Meta.CorrelationID),
			slog.String("helm.event.run_id", event.Meta.RunID),
			slog.Int("helm.event.schema_version", event.Meta.SchemaVersion),
			slog.String("helm.event.env", event.Meta.Env),
			slog.String("helm.event.tenant_id", event.Meta.TenantID),
			slog.String("helm.event.source_ref", event.Meta.SourceRef),
		}
		keys := make([]string, 0, len(event.Fields))
		for key := range event.Fields {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			attrs = append(attrs, slog.Any("helm.event.field."+key, event.Fields[key]))
		}

		resolvedLogger.LogAttrs(ctx, slog.LevelInfo, "helm.lifecycle.event", attrs...)
		return nil
	}
}

func validatePublishedEvent(event LifecycleEvent) error {
	if event.Meta.Env != EnvSynthetic {
		return fmt.Errorf("%w: %q", ErrUnsupportedEventDataClass, event.Meta.Env)
	}
	if !isLifecycleEventType(event.Meta.EventType) || !correlation.IsValid(event.Meta.CorrelationID) {
		return ErrInvalidLifecycleEvent
	}
	if event.Meta.EventID == "" || len(event.Meta.EventID) > 128 || strings.ContainsAny(event.Meta.EventID, "\r\n") {
		return ErrInvalidLifecycleEvent
	}
	if event.Meta.RunID != "" && !boundedRef(event.Meta.RunID) {
		return ErrInvalidLifecycleEvent
	}
	if !safeFieldString(event.Meta.TenantID) || (event.Meta.TenantID != "" && !boundedRef(event.Meta.TenantID)) {
		return ErrInvalidLifecycleEvent
	}
	if !safeFieldString(event.Meta.SourceRef) {
		return ErrInvalidLifecycleEvent
	}
	for key, value := range event.Fields {
		if unsafeFieldName(key) || !allowedFieldName(key) || !safeFieldValue(key, value) {
			return fmt.Errorf("%w: %q", ErrUnsafeEventField, key)
		}
	}
	return nil
}

func isLifecycleEventType(eventType string) bool {
	for _, known := range LifecycleEventTypes() {
		if eventType == known {
			return true
		}
	}
	return false
}

func allowedFieldName(key string) bool {
	switch key {
	case "actor_ref", "surface", "tool", "action", "resource", "effect_context", "classification_source",
		"effect_class", "risk_tier", "decision_id", "policy_backend", "policy_version", "policy_content_hash",
		"policy_epoch", "rules_fired", "decision_latency_ms", "verdict", "reason_code",
		"subject_id", "policy_decision_hash", "approval_ref", "approver_ref",
		"approval_expiry_ms", "receipt_id", "status", "intent_hash", "args_hash", "effect_id",
		"effect_type", "retry_number", "failure_class", "attempt_id", "attempt",
		"execution_id", "retry_count", "duration_ms", "tokens_in", "tokens_out", "outcome":
		return true
	default:
		return false
	}
}

func unsafeFieldName(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return true
	}
	for _, prohibited := range []string{"reason", "message", "detail", "error", "failure_reason"} {
		if key == prohibited {
			return true
		}
	}
	for _, prohibited := range []string{"payload", "arguments", "argument", "args", "secret", "session", "principal", "response", "raw"} {
		if strings.Contains(key, prohibited) {
			return true
		}
	}
	return false
}

func safeFieldValue(key string, value any) bool {
	switch typed := value.(type) {
	case nil, bool, int, int64, float64:
		return true
	case string:
		if (key == "actor_ref" || key == "approver_ref" || key == "attempt_id" || key == "subject_id") && typed != "" && !boundedRef(typed) {
			return false
		}
		return safeFieldString(typed)
	case []string:
		if len(typed) > 64 {
			return false
		}
		for _, item := range typed {
			if !safeFieldString(item) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func safeFieldString(value string) bool {
	return len(value) <= 128 && !strings.ContainsAny(value, "\r\n")
}

func boundedRef(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 || !safeFieldString(value) {
		return false
	}
	_, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil
}
