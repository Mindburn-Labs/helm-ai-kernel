package contracts

import (
	"fmt"
	"strings"
	"time"
)

// ObservedAssumption is a claim about external state that an authorization
// depends on, in a form that can be re-checked.
//
// PlanTransaction.AssumptionSet and VerificationScope.Assumptions are
// []string — prose. Prose cannot go stale in any way a machine can detect,
// which is why ERR_ASSUMPTION_STALE was declared, given a conformance vector,
// and never emitted: nothing in the tree could express an assumption that is
// re-checkable.
//
// The shape here is the staleness triple already specified by
// protocols/specs/observations/observation_artifact.v1.schema.json —
// captured_at, ttl_seconds, content_hash — which is when the world was
// observed, how long that observation is good for, and a digest of what was
// seen. That schema had no Go type. This is the subset an authorization gate
// needs; grounded selectors and viewport geometry stay in the schema until a
// GUI-action path needs them.
type ObservedAssumption struct {
	AssumptionID string `json:"assumption_id"`
	// Subject names what was observed, so an observer knows what to re-read.
	Subject string `json:"subject"`
	// ObservationType matches the schema enum.
	ObservationType string `json:"observation_type"`
	// ContentHash digests the observed state. Re-observing and getting a
	// different digest means the world moved under the plan.
	ContentHash string    `json:"content_hash"`
	CapturedAt  time.Time `json:"captured_at"`
	// TTLSeconds is how long the observation is considered valid. Zero means
	// the observation carries no validity window and is treated as expired
	// immediately — an assumption with no freshness bound is not an assumption.
	TTLSeconds int `json:"ttl_seconds"`
	// AssumptionHash is the sealed JCS digest, bound into a denial as evidence.
	AssumptionHash string `json:"assumption_hash,omitempty"`
}

const observationTypes = "dom_snapshot accessibility_tree screenshot api_response"

// Validate enforces the shape a re-check depends on.
func (a ObservedAssumption) Validate() error {
	if strings.TrimSpace(a.AssumptionID) == "" {
		return fmt.Errorf("observed assumption requires assumption_id")
	}
	if strings.TrimSpace(a.Subject) == "" {
		return fmt.Errorf("observed assumption %q requires subject", a.AssumptionID)
	}
	if !strings.Contains(observationTypes, a.ObservationType) || a.ObservationType == "" {
		return fmt.Errorf("observed assumption %q has unknown observation_type %q", a.AssumptionID, a.ObservationType)
	}
	if !strings.HasPrefix(a.ContentHash, "sha256:") || len(a.ContentHash) != len("sha256:")+64 {
		return fmt.Errorf("observed assumption %q requires a sha256: content_hash", a.AssumptionID)
	}
	if a.CapturedAt.IsZero() {
		return fmt.Errorf("observed assumption %q requires captured_at", a.AssumptionID)
	}
	if a.TTLSeconds < 0 {
		return fmt.Errorf("observed assumption %q has negative ttl_seconds", a.AssumptionID)
	}
	return nil
}

// Seal computes AssumptionHash over the assumption with the field itself
// zeroed, matching the Seal idiom used across the harness contracts.
func (a *ObservedAssumption) Seal() error {
	if a == nil {
		return fmt.Errorf("cannot seal a nil observed assumption")
	}
	a.AssumptionHash = ""
	hash, err := hashJCS(*a)
	if err != nil {
		return fmt.Errorf("sealing observed assumption: %w", err)
	}
	a.AssumptionHash = hash
	return nil
}

// ExpiresAt is when the observation stops being usable.
func (a ObservedAssumption) ExpiresAt() time.Time {
	return a.CapturedAt.Add(time.Duration(a.TTLSeconds) * time.Second)
}

// Expired reports whether the observation's validity window has closed at now.
// A zero TTL expires at capture, so an assumption carrying no window is never
// fresh rather than always fresh.
func (a ObservedAssumption) Expired(now time.Time) bool {
	return !now.Before(a.ExpiresAt())
}
