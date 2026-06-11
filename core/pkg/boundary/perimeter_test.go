package boundary

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPerimeterEnforcer_Network(t *testing.T) {
	policy := &PerimeterPolicy{
		Version:  PolicyVersion,
		PolicyID: "perm-test-01",
		Name:     "Test Policy",
		Enforcement: Enforcement{
			Mode: ModeEnforce,
		},
		Constraints: Constraints{
			Network: &NetworkConstraints{
				RequireTLS:   true,
				AllowedHosts: []string{"*.example.com", "api.github.com"},
				DeniedHosts:  []string{"malicious.example.com"},
			},
		},
	}

	pe, err := NewPerimeterEnforcer(policy)
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		desc      string
		url       string
		allow     bool
		errSubstr string
	}{
		{
			desc:  "Allowed host and TLS",
			url:   "https://api.example.com/v1/data",
			allow: true,
		},
		{
			desc:  "Exact allowed host",
			url:   "https://api.github.com/users",
			allow: true,
		},
		{
			desc:      "No TLS denied",
			url:       "http://api.example.com",
			allow:     false,
			errSubstr: "TLS required",
		},
		{
			desc:      "Denied host even if matches wildcard",
			url:       "https://malicious.example.com",
			allow:     false,
			errSubstr: "host explicitly denied",
		},
		{
			desc:      "Host not in allowlist",
			url:       "https://google.com",
			allow:     false,
			errSubstr: "host not in allowlist",
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := pe.CheckNetwork(ctx, tc.url)
			if tc.allow {
				if err != nil {
					t.Errorf("CheckNetwork(%q) returned unexpected error: %v", tc.url, err)
				}
			} else {
				if err == nil {
					t.Errorf("CheckNetwork(%q) accepted, expected error", tc.url)
				}
			}
		})
	}
}

func TestPerimeterEnforcer_Tools(t *testing.T) {
	policy := &PerimeterPolicy{
		Version: PolicyVersion,
		Enforcement: Enforcement{
			Mode: ModeEnforce,
		},
		Constraints: Constraints{
			Tools: &ToolConstraints{
				RequireAttestation: true,
				AllowedTools:       []string{"tool-a", "tool-b"},
				DeniedTools:        []string{"tool-bad"},
			},
		},
	}

	pe, _ := NewPerimeterEnforcer(policy)
	ctx := context.Background()

	// Test 1: Allowed attested tool
	if err := pe.CheckTool(ctx, "tool-a", true); err != nil {
		t.Errorf("Allowed tool rejected: %v", err)
	}

	// Test 2: Unattested tool
	if err := pe.CheckTool(ctx, "tool-a", false); err == nil {
		t.Errorf("Unattested tool accepted")
	}

	// Test 3: Denied tool
	if err := pe.CheckTool(ctx, "tool-bad", true); err == nil {
		t.Errorf("Denied tool accepted")
	}

	// Test 4: Unknown tool
	if err := pe.CheckTool(ctx, "tool-c", true); err == nil {
		t.Errorf("Unknown tool accepted")
	}
}

func TestPerimeterEnforcer_Data(t *testing.T) {
	policy := &PerimeterPolicy{
		Version: PolicyVersion,
		Enforcement: Enforcement{
			Mode: ModeEnforce,
		},
		Constraints: Constraints{
			Data: &DataConstraints{
				AllowedClasses: []string{"public", "internal"},
				DeniedClasses:  []string{"restricted"},
			},
		},
	}

	pe, _ := NewPerimeterEnforcer(policy)
	ctx := context.Background()

	if err := pe.CheckData(ctx, "public"); err != nil {
		t.Errorf("Allowed data class rejected")
	}

	if err := pe.CheckData(ctx, "classified"); err == nil {
		t.Errorf("Unknown data class accepted")
	}

	if err := pe.CheckData(ctx, "restricted"); err == nil {
		t.Errorf("Denied data class accepted")
	}
}

func TestPerimeterEnforcer_RejectsUnsupportedDeclaredControls(t *testing.T) {
	tests := []struct {
		name        string
		constraints Constraints
		field       string
	}{
		{
			name:        "network rate",
			constraints: Constraints{Network: &NetworkConstraints{MaxRequestsPerMin: 1}},
			field:       "network.max_requests_per_minute",
		},
		{
			name:        "network bandwidth",
			constraints: Constraints{Network: &NetworkConstraints{MaxBandwidthBytes: 1024}},
			field:       "network.max_bandwidth_bytes",
		},
		{
			name:        "tool concurrency",
			constraints: Constraints{Tools: &ToolConstraints{MaxConcurrentCalls: 1}},
			field:       "tools.max_concurrent_calls",
		},
		{
			name:        "tool timeout",
			constraints: Constraints{Tools: &ToolConstraints{TimeoutSeconds: 10}},
			field:       "tools.timeout_seconds",
		},
		{
			name:        "context token limit",
			constraints: Constraints{Data: &DataConstraints{MaxContextTokens: 128}},
			field:       "data.max_context_tokens",
		},
		{
			name:        "response token limit",
			constraints: Constraints{Data: &DataConstraints{MaxResponseTokens: 128}},
			field:       "data.max_response_tokens",
		},
		{
			name:        "redaction patterns",
			constraints: Constraints{Data: &DataConstraints{RedactPatterns: []string{"secret"}}},
			field:       "data.redact_patterns",
		},
		{
			name:        "temporal controls",
			constraints: Constraints{Temporal: &TemporalConstraints{AllowedDays: []string{"monday"}}},
			field:       "temporal",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPerimeterEnforcer(&PerimeterPolicy{
				Version:     PolicyVersion,
				PolicyID:    "reject-unsupported",
				Enforcement: Enforcement{Mode: ModeEnforce},
				Constraints: tc.constraints,
			})
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("expected ErrInvalidPolicy, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("expected error to mention %q, got %v", tc.field, err)
			}
		})
	}
}

func TestPerimeterAuditModeLogging(t *testing.T) {
	policy := &PerimeterPolicy{
		Version:  PolicyVersion,
		PolicyID: "audit-test-01",
		Enforcement: Enforcement{
			Mode: ModeAudit,
		},
		Constraints: Constraints{
			Tools: &ToolConstraints{
				AllowedTools: []string{"allowed-tool"},
			},
		},
	}

	pe, err := NewPerimeterEnforcer(policy)
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	ctx := context.Background()

	type violationCallback struct {
		err      error
		reason   string
		policyID string
	}
	callbacks := make(chan violationCallback, 1)

	pe.SetViolationHandler(func(c context.Context, err error, reason string, policyID string) {
		callbacks <- violationCallback{err: err, reason: reason, policyID: policyID}
	})

	// Check a tool that is not in the allowlist. Since it's ModeAudit, this should NOT return an error.
	err = pe.CheckTool(ctx, "unauthorized-tool", true)
	if err != nil {
		t.Fatalf("CheckTool returned error %v in audit mode, expected nil", err)
	}

	var callback violationCallback
	select {
	case callback = <-callbacks:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Violation handler callback was not invoked")
	}

	if callback.err != ErrToolDenied {
		t.Errorf("Expected ErrToolDenied, got %v", callback.err)
	}
	if callback.policyID != "audit-test-01" {
		t.Errorf("Expected policyID audit-test-01, got %q", callback.policyID)
	}
	if !strings.Contains(callback.reason, "unauthorized-tool") {
		t.Errorf("Expected reason to contain unauthorized-tool, got %q", callback.reason)
	}
}

func TestMatchHost(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		match   bool
	}{
		{"*", "example.com", true},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", true},
		{"*.example.com", "another.domain.com", false},
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "example.com", false},
	}

	for _, tc := range tests {
		res := matchHost(tc.pattern, tc.host)
		if res != tc.match {
			t.Errorf("matchHost(%q, %q) = %t, expected %t", tc.pattern, tc.host, res, tc.match)
		}
	}
}
