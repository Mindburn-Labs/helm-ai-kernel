package boundary

import (
	"context"
	"testing"
)

func FuzzPerimeterCheck(f *testing.F) {
	f.Add("https://example.com", "tool-a", "public")
	f.Add("http://api.github.com/users", "tool-bad", "restricted")
	f.Add("https://malicious.example.com", "allowed-tool", "internal")

	policy := &PerimeterPolicy{
		Version:  PolicyVersion,
		PolicyID: "fuzz-policy",
		Enforcement: Enforcement{
			Mode: ModeEnforce,
		},
		Constraints: Constraints{
			Network: &NetworkConstraints{
				RequireTLS:   true,
				AllowedHosts: []string{"*.example.com", "api.github.com"},
				DeniedHosts:  []string{"malicious.example.com"},
			},
			Tools: &ToolConstraints{
				AllowedTools: []string{"tool-a", "tool-b"},
				DeniedTools:  []string{"tool-bad"},
			},
			Data: &DataConstraints{
				AllowedClasses: []string{"public", "internal"},
				DeniedClasses:  []string{"restricted"},
			},
		},
	}

	pe, err := NewPerimeterEnforcer(policy)
	if err != nil {
		return
	}

	ctx := context.Background()

	f.Fuzz(func(t *testing.T, targetURL string, toolID string, dataClass string) {
		_ = pe.CheckNetwork(ctx, targetURL)
		_ = pe.CheckTool(ctx, toolID, true)
		_ = pe.CheckTool(ctx, toolID, false)
		_ = pe.CheckData(ctx, dataClass)
	})
}

func FuzzMatchHost(f *testing.F) {
	f.Add("*.example.com", "api.example.com")
	f.Add("example.com", "example.com")
	f.Add("*", "anyhost.com")

	f.Fuzz(func(t *testing.T, pattern string, host string) {
		_ = matchHost(pattern, host)
	})
}
