// Package antispoof provides a red-team pack that tests channel security by
// simulating spoofing attacks against AntiSpoofValidator implementations.
//
// Each Scenario describes a single attack vector.  The Pack runs all scenarios
// in sequence and produces a PackResult that summarises which attacks were
// blocked and which (if any) bypassed the validator.
package antispoof

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/channels"
)

// Scenario describes one spoofing simulation.
type Scenario struct {
	Name        string `json:"name"`
	Channel     string `json:"channel"` // slack, telegram, lark
	Attack      string `json:"attack"`  // identity_spoof, timestamp_replay, payload_injection, thread_hijack
	Description string `json:"description"`
}

// ScenarioResult captures the outcome of a single scenario run.
type ScenarioResult struct {
	ScenarioName string `json:"scenario_name"`
	// Blocked is true when the validator correctly rejected the spoofed envelope.
	Blocked    bool   `json:"blocked"`
	DetectedAs string `json:"detected_as"` // suspicious, unknown, etc.
	ResponseMs int64  `json:"response_ms"`
	Details    string `json:"details"`
}

// PackResult summarises the outcome of running all scenarios in the pack.
type PackResult struct {
	PackID         string           `json:"pack_id"`
	TotalScenarios int              `json:"total_scenarios"`
	Blocked        int              `json:"blocked"`
	Bypassed       int              `json:"bypassed"`
	Results        []ScenarioResult `json:"results"`
	// ContentHash is a deterministic SHA-256 of the canonical result JSON.
	// It is stable as long as scenario names, blocked flags, and detected_as fields are unchanged.
	ContentHash string `json:"content_hash"`
}

// AntiSpoofPack runs a suite of spoofing simulations against channel adapters.
type AntiSpoofPack struct {
	Scenarios []Scenario
}

// DefaultScenarios returns the built-in set of 8 red-team scenarios.
func DefaultScenarios() []Scenario {
	return []Scenario{
		{
			Name:        "slack_identity_spoof",
			Channel:     "slack",
			Attack:      "identity_spoof",
			Description: "Forge a Slack message with a spoofed sender_id (empty sender)",
		},
		{
			Name:        "slack_timestamp_replay",
			Channel:     "slack",
			Attack:      "timestamp_replay",
			Description: "Replay a Slack message with a timestamp older than the allowed clock-skew window",
		},
		{
			Name:        "telegram_identity_spoof",
			Channel:     "telegram",
			Attack:      "identity_spoof",
			Description: "Forge a Telegram message with a missing sender_id",
		},
		{
			Name:        "telegram_payload_injection",
			Channel:     "telegram",
			Attack:      "payload_injection",
			Description: "Inject malicious JSON in Telegram envelope metadata (empty envelope_id)",
		},
		{
			Name:        "lark_identity_spoof",
			Channel:     "lark",
			Attack:      "identity_spoof",
			Description: "Forge a Lark message with a spoofed sender_id (empty sender)",
		},
		{
			Name:        "lark_thread_hijack",
			Channel:     "lark",
			Attack:      "thread_hijack",
			Description: "Inject into an existing Lark thread with wrong sender (empty sender_id)",
		},
		{
			Name:        "generic_empty_envelope",
			Channel:     "slack",
			Attack:      "identity_spoof",
			Description: "Send an envelope with all required identity fields missing",
		},
		{
			Name:        "generic_future_timestamp",
			Channel:     "telegram",
			Attack:      "timestamp_replay",
			Description: "Send a message timestamped well in the future (>1 s clock-drift tolerance)",
		},
	}
}

// buildSpoofedEnvelope constructs a ChannelEnvelope that represents the attack
// described by s.  The returned envelope is intentionally malformed so that a
// correct AntiSpoofValidator will reject it.
func buildSpoofedEnvelope(s Scenario) channels.ChannelEnvelope {
	nowMs := time.Now().UnixMilli()

	// Start from a structurally valid base for the given channel.
	base := channels.ChannelEnvelope{
		EnvelopeID:       "antispoof-env-" + s.Name,
		Channel:          channels.ChannelKind(s.Channel),
		TenantID:         "antispoof-tenant",
		SessionID:        "antispoof-session",
		MessageID:        "antispoof-msg-" + s.Name,
		SenderID:         "antispoof-sender",
		SenderTrust:      channels.SenderTrustUnknown,
		ReceivedAtUnixMs: nowMs,
	}

	switch s.Name {
	case "slack_identity_spoof":
		// Remove the sender identity — validator must reject.
		base.SenderID = ""

	case "slack_timestamp_replay":
		// Set timestamp to 10 minutes in the past — well outside the 5-minute window.
		base.ReceivedAtUnixMs = nowMs - 10*60*1000

	case "telegram_identity_spoof":
		// Missing sender_id simulates a forged Telegram message.
		base.SenderID = ""

	case "telegram_payload_injection":
		// Wipe envelope_id to simulate corrupted/injected payload.
		base.EnvelopeID = ""

	case "lark_identity_spoof":
		// Missing sender_id — Lark identity forge.
		base.SenderID = ""

	case "lark_thread_hijack":
		// Thread hijack: wrong sender (empty) attempting to write into a thread.
		base.SenderID = ""
		base.ThreadID = "existing-thread-001"

	case "generic_empty_envelope":
		// Strip all identity fields.
		base.EnvelopeID = ""
		base.SenderID = ""

	case "generic_future_timestamp":
		// Timestamp 10 minutes into the future — far beyond the 1 s tolerance.
		base.ReceivedAtUnixMs = nowMs + 10*60*1000
	}

	return base
}

// Run executes all scenarios in p.Scenarios against the provided validator.
// Each scenario submits a crafted (spoofed) envelope; a Blocked result means
// the validator correctly rejected it.
func (p *AntiSpoofPack) Run(ctx context.Context, validator channels.AntiSpoofValidator) (*PackResult, error) {
	results := make([]ScenarioResult, 0, len(p.Scenarios))
	blocked := 0
	bypassed := 0

	for _, scenario := range p.Scenarios {
		env := buildSpoofedEnvelope(scenario)
		start := time.Now()

		antiResult, err := validator.Validate(ctx, env)
		elapsed := time.Since(start).Milliseconds()

		if err != nil {
			return nil, fmt.Errorf("antispoof: scenario %q: validator returned internal error: %w", scenario.Name, err)
		}

		// A correctly functioning validator will set Passed=false for all spoofed envelopes.
		wasBlocked := !antiResult.Passed

		detectedAs := string(antiResult.SenderTrust)
		if antiResult.Passed {
			detectedAs = "passed" // should not happen for spoofed envelopes
		}

		sr := ScenarioResult{
			ScenarioName: scenario.Name,
			Blocked:      wasBlocked,
			DetectedAs:   detectedAs,
			ResponseMs:   elapsed,
			Details:      antiResult.Reason,
		}
		results = append(results, sr)

		if wasBlocked {
			blocked++
		} else {
			bypassed++
		}
	}

	packResult := &PackResult{
		PackID:         "antispoof-v1",
		TotalScenarios: len(p.Scenarios),
		Blocked:        blocked,
		Bypassed:       bypassed,
		Results:        results,
	}
	packResult.ContentHash = computePackResultHash(packResult)

	return packResult, nil
}

// computePackResultHash produces a deterministic SHA-256 over the stable
// fields of a PackResult (scenario names, blocked flags, detected_as values).
// It excludes ResponseMs and Details which may vary between runs.
func computePackResultHash(r *PackResult) string {
	type stableResult struct {
		ScenarioName string `json:"scenario_name"`
		Blocked      bool   `json:"blocked"`
		DetectedAs   string `json:"detected_as"`
	}

	type stableRecord struct {
		PackID         string         `json:"pack_id"`
		TotalScenarios int            `json:"total_scenarios"`
		Blocked        int            `json:"blocked"`
		Bypassed       int            `json:"bypassed"`
		Results        []stableResult `json:"results"`
	}

	stable := stableRecord{
		PackID:         r.PackID,
		TotalScenarios: r.TotalScenarios,
		Blocked:        r.Blocked,
		Bypassed:       r.Bypassed,
		Results:        make([]stableResult, len(r.Results)),
	}
	for i, res := range r.Results {
		stable.Results[i] = stableResult{
			ScenarioName: res.ScenarioName,
			Blocked:      res.Blocked,
			DetectedAs:   res.DetectedAs,
		}
	}

	data, _ := json.Marshal(stable)
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}
