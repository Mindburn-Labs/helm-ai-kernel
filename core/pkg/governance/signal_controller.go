package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

type SignalController struct {
	ProducerID string
	signer     crypto.Signer
}

func NewSignalController(id string, signer crypto.Signer) *SignalController {
	return &SignalController{ProducerID: id, signer: signer}
}

func (s *SignalController) Name() string {
	return "signal.controller"
}

func (s *SignalController) Advise(ctx context.Context, intent string, contextData map[string]any) (*artifacts.ArtifactEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("signal controller: context canceled: %w", err)
	}

	payload := assessSignal(intent, contextData)
	bytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("signal controller: marshal failed: %w", err)
	}

	env := &artifacts.ArtifactEnvelope{
		Type:          artifacts.TypeAlertEvidence,
		SchemaVersion: "v1",
		Payload:       bytes,
		ProducerID:    s.ProducerID,
		Timestamp:     time.Now().UTC(),
	}
	if err := artifacts.SignEnvelope(env, s.signer); err != nil {
		return nil, err
	}
	return env, nil
}

type signalAdvicePayload struct {
	Signal  string         `json:"signal"`
	Health  float64        `json:"health"`
	Check   string         `json:"check"`
	Intent  string         `json:"intent"`
	Metrics map[string]any `json:"metrics"`
	Reasons []string       `json:"reasons,omitempty"`
}

func assessSignal(intent string, contextData map[string]any) signalAdvicePayload {
	health, hasHealth := metricFloat(contextData, "health", "health_percent", "availability")
	errorRate, hasErrorRate := metricFloat(contextData, "error_rate", "errorRate")
	latencyMS, hasLatency := metricFloat(contextData, "latency_ms", "p95_latency_ms", "p99_latency_ms")
	saturation, hasSaturation := metricFloat(contextData, "saturation", "cpu_saturation", "memory_saturation")
	incident, hasIncident := metricBool(contextData, "incident", "active_incident", "active_incidents")
	safe, hasSafe := metricBool(contextData, "safe", "is_safe")
	unsafe, hasUnsafe := metricBool(contextData, "unsafe", "is_unsafe")
	requiresApproval, _ := metricBool(contextData, "requires_approval", "approval_required")
	approved, hasApproved := metricBool(contextData, "approved", "human_approved")

	if !hasHealth {
		health = 0
	}

	signal := "GREEN"
	reasons := []string{}
	addWarn := func(reason string) {
		if signal == "GREEN" {
			signal = "WARN"
		}
		reasons = append(reasons, reason)
	}
	addCritical := func(reason string) {
		signal = "CRITICAL"
		reasons = append(reasons, reason)
	}

	if !hasHealth {
		addWarn("health_metric_missing")
	} else if health < 80 {
		addCritical("health_below_critical_threshold")
	} else if health < 95 {
		addWarn("health_below_warning_threshold")
	}
	if hasErrorRate {
		if errorRate >= 0.10 {
			addCritical("error_rate_critical")
		} else if errorRate >= 0.02 {
			addWarn("error_rate_elevated")
		}
	}
	if hasLatency {
		if latencyMS >= 5000 {
			addCritical("latency_critical")
		} else if latencyMS >= 1000 {
			addWarn("latency_elevated")
		}
	}
	if hasSaturation {
		if saturation >= 0.95 {
			addCritical("saturation_critical")
		} else if saturation >= 0.85 {
			addWarn("saturation_elevated")
		}
	}
	if hasIncident && incident {
		addCritical("active_incident")
	}
	if hasSafe && !safe {
		addCritical("safety_signal_false")
	}
	if hasUnsafe && unsafe {
		addCritical("unsafe_signal_true")
	}
	if requiresApproval && (!hasApproved || !approved) {
		addCritical("approval_required_not_approved")
	}
	if riskyIntent(intent) && (!hasApproved || !approved) {
		addWarn("risky_intent_without_approval")
	}

	check := "metrics_nominal"
	if signal != "GREEN" {
		check = "metrics_degraded"
	}

	return signalAdvicePayload{
		Signal: signal,
		Health: health,
		Check:  check,
		Intent: intent,
		Metrics: map[string]any{
			"health":            health,
			"health_present":    hasHealth,
			"error_rate":        metricValueOrNil(errorRate, hasErrorRate),
			"latency_ms":        metricValueOrNil(latencyMS, hasLatency),
			"saturation":        metricValueOrNil(saturation, hasSaturation),
			"active_incident":   boolValueOrNil(incident, hasIncident),
			"safe":              boolValueOrNil(safe, hasSafe),
			"unsafe":            boolValueOrNil(unsafe, hasUnsafe),
			"requires_approval": requiresApproval,
			"approved":          boolValueOrNil(approved, hasApproved),
		},
		Reasons: reasons,
	}
}

func metricFloat(data map[string]any, keys ...string) (float64, bool) {
	for _, key := range keys {
		value, ok := data[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case float64:
			return typed, true
		case float32:
			return float64(typed), true
		case int:
			return float64(typed), true
		case int64:
			return float64(typed), true
		case uint64:
			return float64(typed), true
		case json.Number:
			if f, err := typed.Float64(); err == nil {
				return f, true
			}
		}
	}
	return 0, false
}

func metricBool(data map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		value, ok := data[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case bool:
			return typed, true
		case string:
			switch strings.ToLower(strings.TrimSpace(typed)) {
			case "1", "true", "yes":
				return true, true
			case "0", "false", "no":
				return false, true
			}
		}
	}
	return false, false
}

func metricValueOrNil(value float64, ok bool) any {
	if !ok {
		return nil
	}
	return value
}

func boolValueOrNil(value bool, ok bool) any {
	if !ok {
		return nil
	}
	return value
}

func riskyIntent(intent string) bool {
	normalized := strings.ToLower(intent)
	for _, marker := range []string{"delete", "destroy", "shutdown", "production", "privileged"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}
