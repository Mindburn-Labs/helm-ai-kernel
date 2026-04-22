package boundary

import (
	"context"
	"testing"
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
