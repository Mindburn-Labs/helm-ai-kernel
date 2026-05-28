package pdp

import (
	"context"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	decisionsCounter *prometheus.CounterVec
	once             sync.Once
)

func initMetrics() {
	once.Do(func() {
		decisionsCounter = promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "helm_kernel_decisions_total",
				Help: "Total number of AI Kernel policy decisions evaluated by the PDP.",
			},
			[]string{"verdict", "reason_code", "backend"},
		)
	})
}

// TelemetryPDP wraps any PolicyDecisionPoint to collect metrics and optionally execute in Shadow Mode.
type TelemetryPDP struct {
	inner      PolicyDecisionPoint
	shadowMode bool
}

// NewTelemetryPDP creates a decorator for PolicyDecisionPoint.
func NewTelemetryPDP(inner PolicyDecisionPoint, shadowMode bool) *TelemetryPDP {
	initMetrics()
	return &TelemetryPDP{
		inner:      inner,
		shadowMode: shadowMode,
	}
}

// Evaluate runs the inner policy evaluation, records metrics, and applies Shadow Mode transformation if active.
func (t *TelemetryPDP) Evaluate(ctx context.Context, req *DecisionRequest) (*DecisionResponse, error) {
	resp, err := t.inner.Evaluate(ctx, req)
	if err != nil {
		if decisionsCounter != nil {
			decisionsCounter.WithLabelValues("DENY", "PDP_ERROR", string(t.inner.Backend())).Inc()
		}
		return nil, err
	}

	actualVerdict := "ALLOW"
	if !resp.Allow {
		if resp.ReasonCode == "APPROVAL_REQUIRED" {
			actualVerdict = "ESCALATE"
		} else {
			actualVerdict = "DENY"
		}
	}

	metricVerdict := actualVerdict
	if t.shadowMode && !resp.Allow {
		// In Shadow Mode, we log it as *_shadow but permit the operation (Allow = true)
		metricVerdict = strings.ToLower(actualVerdict) + "_shadow"
		resp.Allow = true

		// Update the decision hash because we altered the 'Allow' field
		if err := attachDecisionHash(resp); err != nil {
			return denyForHashFailure(resp.PolicyRef, err)
		}
	}

	if decisionsCounter != nil {
		decisionsCounter.WithLabelValues(metricVerdict, resp.ReasonCode, string(t.inner.Backend())).Inc()
	}

	return resp, nil
}

// Backend returns the inner PDP backend.
func (t *TelemetryPDP) Backend() Backend {
	return t.inner.Backend()
}

// PolicyHash returns the inner PDP policy hash.
func (t *TelemetryPDP) PolicyHash() string {
	return t.inner.PolicyHash()
}

// SetShadowMode toggles shadow mode at runtime.
func (t *TelemetryPDP) SetShadowMode(enabled bool) {
	t.shadowMode = enabled
}

// IsShadowMode reports whether shadow mode is active.
func (t *TelemetryPDP) IsShadowMode() bool {
	return t.shadowMode
}
