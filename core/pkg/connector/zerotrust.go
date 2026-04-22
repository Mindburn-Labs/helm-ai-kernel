// Package connector provides zero-trust enforcement for connectors.
//
// Per HELM 2030 Spec — Connector Zero-Trust:
//   - Every connector call carries provenance tags
//   - Freshness TTL enforces data staleness limits
//   - Trust policies define per-connector constraints
//   - Poisoning defenses detect anomalous responses
package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// TrustLevel categorizes connector trust.
type TrustLevel string

const (
	TrustLevelFull       TrustLevel = "FULL"
	TrustLevelVerified   TrustLevel = "VERIFIED"
	TrustLevelRestricted TrustLevel = "RESTRICTED"
	TrustLevelUntrusted  TrustLevel = "UNTRUSTED"
)

// ProvenanceTag is attached to every connector response.
type ProvenanceTag struct {
	ConnectorID  string     `json:"connector_id"`
	RequestHash  string     `json:"request_hash"`
	ResponseHash string     `json:"response_hash"`
	FetchedAt    time.Time  `json:"fetched_at"`
	TTL          int        `json:"ttl_seconds"`
	TrustLevel   TrustLevel `json:"trust_level"`
	SourceURI    string     `json:"source_uri,omitempty"`
}

// IsFresh returns whether the data is still within its TTL.
func (p *ProvenanceTag) IsFresh(now time.Time) bool {
	return now.Before(p.FetchedAt.Add(time.Duration(p.TTL) * time.Second))
}

// TrustPolicy defines per-connector trust constraints.
type TrustPolicy struct {
	ConnectorID        string     `json:"connector_id"`
	TrustLevel         TrustLevel `json:"trust_level"`
	MaxTTLSeconds      int        `json:"max_ttl_seconds"`
	AllowedDataClasses []string   `json:"allowed_data_classes,omitempty"`
	RateLimitPerMinute int        `json:"rate_limit_per_minute"`
	RequireProvenance  bool       `json:"require_provenance"`
	MinimizeData       bool       `json:"minimize_data"` // Strip unnecessary fields
	ResidencyRegions   []string   `json:"residency_regions,omitempty"`
}

// AnomalyDetector checks connector responses for poisoning indicators.
type AnomalyDetector struct {
	maxResponseSize int64
	maxLatency      time.Duration
}

// NewAnomalyDetector creates a new detector with defaults.
func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		maxResponseSize: 10 * 1024 * 1024, // 10MB
		maxLatency:      30 * time.Second,
	}
}

// AnomalyCheckResult reports anomaly detection findings.
type AnomalyCheckResult struct {
	Clean    bool     `json:"clean"`
	Findings []string `json:"findings,omitempty"`
}

// Check performs anomaly detection on a connector response.
func (d *AnomalyDetector) Check(responseSize int64, latency time.Duration) *AnomalyCheckResult {
	result := &AnomalyCheckResult{Clean: true}

	if responseSize > d.maxResponseSize {
		result.Clean = false
		result.Findings = append(result.Findings,
			fmt.Sprintf("response size %d exceeds max %d", responseSize, d.maxResponseSize))
	}

	if latency > d.maxLatency {
		result.Clean = false
		result.Findings = append(result.Findings,
			fmt.Sprintf("latency %v exceeds max %v", latency, d.maxLatency))
	}

	return result
}

// ZeroTrustGate enforces trust policies on connector interactions.
type ZeroTrustGate struct {
	mu       sync.RWMutex
	policies map[string]*TrustPolicy
	calls    map[string][]time.Time // connector_id → recent call timestamps
	detector *AnomalyDetector
	clock    func() time.Time
}

// NewZeroTrustGate creates a new connector zero-trust gate.
func NewZeroTrustGate() *ZeroTrustGate {
	return &ZeroTrustGate{
		policies: make(map[string]*TrustPolicy),
		calls:    make(map[string][]time.Time),
		detector: NewAnomalyDetector(),
		clock:    time.Now,
	}
}

// WithClock overrides clock for testing.
func (g *ZeroTrustGate) WithClock(clock func() time.Time) *ZeroTrustGate {
	g.clock = clock
	return g
}

// SetPolicy sets the trust policy for a connector.
func (g *ZeroTrustGate) SetPolicy(policy *TrustPolicy) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.policies[policy.ConnectorID] = policy
}

// GateDecision is the result of checking a connector call.
type GateDecision struct {
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
	Violation string `json:"violation,omitempty"`
}

// CheckCall verifies if a connector call is permitted.
func (g *ZeroTrustGate) CheckCall(ctx context.Context, connectorID, dataClass string) *GateDecision {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.clock()

	policy, ok := g.policies[connectorID]
	if !ok {
		return &GateDecision{
			Allowed:   false,
			Reason:    "no trust policy for connector",
			Violation: "NO_POLICY",
		}
	}

	if policy.TrustLevel == TrustLevelUntrusted {
		return &GateDecision{
			Allowed:   false,
			Reason:    "connector is untrusted",
			Violation: "UNTRUSTED",
		}
	}

	// Check data class allowlist
	if len(policy.AllowedDataClasses) > 0 && dataClass != "" {
		allowed := false
		for _, dc := range policy.AllowedDataClasses {
			if dc == dataClass {
				allowed = true
				break
			}
		}
		if !allowed {
			return &GateDecision{
				Allowed:   false,
				Reason:    fmt.Sprintf("data class %q not allowed for connector", dataClass),
				Violation: "DATA_CLASS",
			}
		}
	}

	// Check rate limit
	if policy.RateLimitPerMinute > 0 {
		cutoff := now.Add(-1 * time.Minute)
		recentCalls := g.calls[connectorID]
		recent := 0
		for _, t := range recentCalls {
			if t.After(cutoff) {
				recent++
			}
		}
		if recent >= policy.RateLimitPerMinute {
			return &GateDecision{
				Allowed:   false,
				Reason:    fmt.Sprintf("rate limit exceeded: %d/%d per minute", recent, policy.RateLimitPerMinute),
				Violation: "RATE_LIMIT",
			}
		}
	}

	// Record call
	g.calls[connectorID] = append(g.calls[connectorID], now)

	return &GateDecision{
		Allowed: true,
		Reason:  "within trust policy bounds",
	}
}

// ValidateProvenance checks a provenance tag against the connector's trust policy.
func (g *ZeroTrustGate) ValidateProvenance(tag *ProvenanceTag) *GateDecision {
	g.mu.RLock()
	defer g.mu.RUnlock()

	now := g.clock()

	policy, ok := g.policies[tag.ConnectorID]
	if !ok {
		return &GateDecision{
			Allowed:   false,
			Reason:    "no trust policy for connector",
			Violation: "NO_POLICY",
		}
	}

	if policy.RequireProvenance && tag.ResponseHash == "" {
		return &GateDecision{
			Allowed:   false,
			Reason:    "provenance required but response hash missing",
			Violation: "MISSING_PROVENANCE",
		}
	}

	if !tag.IsFresh(now) {
		return &GateDecision{
			Allowed:   false,
			Reason:    "data has exceeded freshness TTL",
			Violation: "STALE_DATA",
		}
	}

	if policy.MaxTTLSeconds > 0 && tag.TTL > policy.MaxTTLSeconds {
		return &GateDecision{
			Allowed:   false,
			Reason:    fmt.Sprintf("TTL %d exceeds policy max %d", tag.TTL, policy.MaxTTLSeconds),
			Violation: "TTL_EXCEEDED",
		}
	}

	return &GateDecision{
		Allowed: true,
		Reason:  "provenance valid",
	}
}

// ComputeProvenanceTag creates a provenance tag for a connector response.
func ComputeProvenanceTag(connectorID string, request, response []byte, ttl int, trustLevel TrustLevel) *ProvenanceTag {
	reqHash := sha256.Sum256(request)
	respHash := sha256.Sum256(response)

	return &ProvenanceTag{
		ConnectorID:  connectorID,
		RequestHash:  "sha256:" + hex.EncodeToString(reqHash[:]),
		ResponseHash: "sha256:" + hex.EncodeToString(respHash[:]),
		FetchedAt:    time.Now(),
		TTL:          ttl,
		TrustLevel:   trustLevel,
	}
}

// ComputePolicyHash computes a deterministic hash of all policies.
func (g *ZeroTrustGate) ComputePolicyHash() (string, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	data, err := json.Marshal(g.policies)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
