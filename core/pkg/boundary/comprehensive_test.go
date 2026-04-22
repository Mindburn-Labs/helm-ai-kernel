package boundary

import (
	"context"
	"testing"
)

func enforcePolicy(t *testing.T, c Constraints) *PerimeterEnforcer {
	t.Helper()
	pe, err := NewPerimeterEnforcer(&PerimeterPolicy{
		Version:     PolicyVersion,
		Enforcement: Enforcement{Mode: ModeEnforce},
		Constraints: c,
	})
	if err != nil {
		t.Fatal(err)
	}
	return pe
}

func TestPerimeterEnforcer_NilPolicy(t *testing.T) {
	pe, err := NewPerimeterEnforcer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pe.CheckNetwork(context.Background(), "http://anything.com"); err != nil {
		t.Fatalf("nil policy should allow all: %v", err)
	}
}

func TestPerimeterEnforcer_DisabledMode(t *testing.T) {
	pe, _ := NewPerimeterEnforcer(&PerimeterPolicy{
		Version:     PolicyVersion,
		Enforcement: Enforcement{Mode: ModeDisabled},
		Constraints: Constraints{Network: &NetworkConstraints{DeniedHosts: []string{"bad.com"}}},
	})
	if err := pe.CheckNetwork(context.Background(), "https://bad.com"); err != nil {
		t.Fatalf("disabled mode should allow all: %v", err)
	}
}

func TestPerimeterEnforcer_AuditMode(t *testing.T) {
	pe, _ := NewPerimeterEnforcer(&PerimeterPolicy{
		Version:     PolicyVersion,
		Enforcement: Enforcement{Mode: ModeAudit},
		Constraints: Constraints{Network: &NetworkConstraints{DeniedHosts: []string{"bad.com"}}},
	})
	if err := pe.CheckNetwork(context.Background(), "https://bad.com"); err != nil {
		t.Fatalf("audit mode should not block: %v", err)
	}
}

func TestPerimeterEnforcer_PortRestriction(t *testing.T) {
	pe := enforcePolicy(t, Constraints{
		Network: &NetworkConstraints{AllowedPorts: []int{443, 8080}},
	})
	if err := pe.CheckNetwork(context.Background(), "https://example.com:443/path"); err != nil {
		t.Fatalf("port 443 should be allowed: %v", err)
	}
	if err := pe.CheckNetwork(context.Background(), "https://example.com:9999/path"); err == nil {
		t.Fatal("port 9999 should be denied")
	}
}

func TestPerimeterEnforcer_WildcardHostDeny(t *testing.T) {
	pe := enforcePolicy(t, Constraints{
		Network: &NetworkConstraints{DeniedHosts: []string{"*"}},
	})
	if err := pe.CheckNetwork(context.Background(), "https://anything.com"); err == nil {
		t.Fatal("wildcard deny should block all hosts")
	}
}

func TestPerimeterEnforcer_ToolNotAttested(t *testing.T) {
	pe := enforcePolicy(t, Constraints{Tools: &ToolConstraints{RequireAttestation: true}})
	if err := pe.CheckTool(context.Background(), "tool-x", false); err == nil {
		t.Fatal("unattested tool should be denied")
	}
}

func TestPerimeterEnforcer_DataDeniedClass(t *testing.T) {
	pe := enforcePolicy(t, Constraints{Data: &DataConstraints{DeniedClasses: []string{"secret"}}})
	if err := pe.CheckData(context.Background(), "secret"); err == nil {
		t.Fatal("denied data class should be rejected")
	}
	if err := pe.CheckData(context.Background(), "public"); err != nil {
		t.Fatalf("non-denied class should be allowed: %v", err)
	}
}

func TestValidateSyscall_FilesystemRead(t *testing.T) {
	if err := ValidateSyscall(OpFilesystemRead, "/etc/hosts"); err != nil {
		t.Fatalf("string path should be valid: %v", err)
	}
	if err := ValidateSyscall(OpFilesystemRead, map[string]any{"path": "/etc/hosts"}); err != nil {
		t.Fatalf("map with path should be valid: %v", err)
	}
	if err := ValidateSyscall(OpFilesystemRead, 42); err == nil {
		t.Fatal("integer payload should fail")
	}
}

func TestValidateSyscall_UnknownOp(t *testing.T) {
	if err := ValidateSyscall(SyscallOp("NUKE"), nil); err == nil {
		t.Fatal("unknown operation should fail")
	}
}

func TestMatchHost_Wildcard(t *testing.T) {
	if !matchHost("*.example.com", "sub.example.com") {
		t.Fatal("wildcard should match subdomain")
	}
	if matchHost("*.example.com", "other.org") {
		t.Fatal("wildcard should not match different domain")
	}
}
