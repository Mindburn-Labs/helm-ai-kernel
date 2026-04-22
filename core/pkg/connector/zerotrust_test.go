package connector

import (
	"context"
	"testing"
	"time"
)

func testPolicy() *TrustPolicy {
	return &TrustPolicy{
		ConnectorID:        "salesforce",
		TrustLevel:         TrustLevelVerified,
		MaxTTLSeconds:      3600,
		AllowedDataClasses: []string{"public", "internal"},
		RateLimitPerMinute: 60,
		RequireProvenance:  true,
		MinimizeData:       true,
		ResidencyRegions:   []string{"us-east-1"},
	}
}

func TestCheckCallNoPolicy(t *testing.T) {
	gate := NewZeroTrustGate()
	decision := gate.CheckCall(context.Background(), "unknown", "public")
	if decision.Allowed {
		t.Fatal("expected denial without policy")
	}
	if decision.Violation != "NO_POLICY" {
		t.Fatalf("expected NO_POLICY, got %s", decision.Violation)
	}
}

func TestCheckCallUntrusted(t *testing.T) {
	gate := NewZeroTrustGate()
	gate.SetPolicy(&TrustPolicy{ConnectorID: "evil", TrustLevel: TrustLevelUntrusted})

	decision := gate.CheckCall(context.Background(), "evil", "public")
	if decision.Allowed {
		t.Fatal("expected denial for untrusted connector")
	}
	if decision.Violation != "UNTRUSTED" {
		t.Fatalf("expected UNTRUSTED, got %s", decision.Violation)
	}
}

func TestCheckCallAllowed(t *testing.T) {
	gate := NewZeroTrustGate()
	gate.SetPolicy(testPolicy())

	decision := gate.CheckCall(context.Background(), "salesforce", "public")
	if !decision.Allowed {
		t.Fatalf("expected allowed, got: %s", decision.Reason)
	}
}

func TestCheckCallDataClassDenied(t *testing.T) {
	gate := NewZeroTrustGate()
	gate.SetPolicy(testPolicy())

	decision := gate.CheckCall(context.Background(), "salesforce", "restricted")
	if decision.Allowed {
		t.Fatal("expected denial for restricted data class")
	}
	if decision.Violation != "DATA_CLASS" {
		t.Fatalf("expected DATA_CLASS, got %s", decision.Violation)
	}
}

func TestCheckCallRateLimit(t *testing.T) {
	now := time.Now()
	gate := NewZeroTrustGate().WithClock(func() time.Time { return now })
	gate.SetPolicy(&TrustPolicy{
		ConnectorID:        "test",
		TrustLevel:         TrustLevelVerified,
		RateLimitPerMinute: 2,
	})

	// First two calls succeed
	d1 := gate.CheckCall(context.Background(), "test", "")
	if !d1.Allowed {
		t.Fatal("first call should be allowed")
	}
	d2 := gate.CheckCall(context.Background(), "test", "")
	if !d2.Allowed {
		t.Fatal("second call should be allowed")
	}

	// Third call exceeds rate limit
	d3 := gate.CheckCall(context.Background(), "test", "")
	if d3.Allowed {
		t.Fatal("expected rate limit exceeded")
	}
	if d3.Violation != "RATE_LIMIT" {
		t.Fatalf("expected RATE_LIMIT, got %s", d3.Violation)
	}
}

func TestValidateProvenanceFresh(t *testing.T) {
	now := time.Now()
	gate := NewZeroTrustGate().WithClock(func() time.Time { return now })
	gate.SetPolicy(testPolicy())

	tag := &ProvenanceTag{
		ConnectorID:  "salesforce",
		ResponseHash: "sha256:abc",
		FetchedAt:    now.Add(-10 * time.Second),
		TTL:          3600,
		TrustLevel:   TrustLevelVerified,
	}

	decision := gate.ValidateProvenance(tag)
	if !decision.Allowed {
		t.Fatalf("expected valid provenance, got: %s", decision.Reason)
	}
}

func TestValidateProvenanceStale(t *testing.T) {
	now := time.Now()
	gate := NewZeroTrustGate().WithClock(func() time.Time { return now })
	gate.SetPolicy(testPolicy())

	tag := &ProvenanceTag{
		ConnectorID:  "salesforce",
		ResponseHash: "sha256:abc",
		FetchedAt:    now.Add(-2 * time.Hour),
		TTL:          3600,
		TrustLevel:   TrustLevelVerified,
	}

	decision := gate.ValidateProvenance(tag)
	if decision.Allowed {
		t.Fatal("expected stale data rejection")
	}
	if decision.Violation != "STALE_DATA" {
		t.Fatalf("expected STALE_DATA, got %s", decision.Violation)
	}
}

func TestValidateProvenanceMissing(t *testing.T) {
	gate := NewZeroTrustGate()
	gate.SetPolicy(testPolicy())

	tag := &ProvenanceTag{
		ConnectorID:  "salesforce",
		ResponseHash: "", // Missing!
		FetchedAt:    time.Now(),
		TTL:          3600,
	}

	decision := gate.ValidateProvenance(tag)
	if decision.Allowed {
		t.Fatal("expected rejection for missing provenance")
	}
	if decision.Violation != "MISSING_PROVENANCE" {
		t.Fatalf("expected MISSING_PROVENANCE, got %s", decision.Violation)
	}
}

func TestValidateProvenanceTTLExceeded(t *testing.T) {
	now := time.Now()
	gate := NewZeroTrustGate().WithClock(func() time.Time { return now })
	gate.SetPolicy(testPolicy()) // MaxTTL = 3600

	tag := &ProvenanceTag{
		ConnectorID:  "salesforce",
		ResponseHash: "sha256:abc",
		FetchedAt:    now,
		TTL:          7200, // Exceeds policy max
		TrustLevel:   TrustLevelVerified,
	}

	decision := gate.ValidateProvenance(tag)
	if decision.Allowed {
		t.Fatal("expected TTL exceeded rejection")
	}
	if decision.Violation != "TTL_EXCEEDED" {
		t.Fatalf("expected TTL_EXCEEDED, got %s", decision.Violation)
	}
}

func TestAnomalyDetectorClean(t *testing.T) {
	d := NewAnomalyDetector()
	result := d.Check(1024, 100*time.Millisecond)
	if !result.Clean {
		t.Fatalf("expected clean, got findings: %v", result.Findings)
	}
}

func TestAnomalyDetectorOversized(t *testing.T) {
	d := NewAnomalyDetector()
	result := d.Check(100*1024*1024, 100*time.Millisecond) // 100MB
	if result.Clean {
		t.Fatal("expected anomaly for oversized response")
	}
}

func TestComputeProvenanceTag(t *testing.T) {
	tag := ComputeProvenanceTag("test", []byte("req"), []byte("resp"), 3600, TrustLevelVerified)
	if tag.ConnectorID != "test" {
		t.Fatal("expected test connector")
	}
	if tag.RequestHash == "" || tag.ResponseHash == "" {
		t.Fatal("expected hashes")
	}
	if tag.TTL != 3600 {
		t.Fatalf("expected TTL 3600, got %d", tag.TTL)
	}
}
