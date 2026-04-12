package federation

import (
	"strings"
	"testing"
)

func TestPolicyInheritor_EffectiveCapabilities(t *testing.T) {
	pi := NewPolicyInheritor()

	policy := FederationPolicy{
		PolicyID:      "pol-1",
		ParentOrgID:   "org-parent",
		ChildOrgID:    "org-child",
		InheritedCaps: []string{"READ", "EXECUTE_TOOL", "WRITE"},
		DeniedCaps:    []string{"WRITE"},
		NarrowingOnly: true,
	}
	if err := pi.SetPolicy(policy); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	parentCaps := []string{"READ", "WRITE", "EXECUTE_TOOL", "ADMIN"}

	// child_effective = (parentCaps intersect inherited) minus denied
	// inherited = {READ, EXECUTE_TOOL, WRITE}
	// intersection with parent = {READ, WRITE, EXECUTE_TOOL}
	// minus denied {WRITE} = {EXECUTE_TOOL, READ}
	effective := pi.EffectiveCapabilities("org-child", parentCaps)

	expected := map[string]bool{
		"EXECUTE_TOOL": true,
		"READ":         true,
	}
	if len(effective) != len(expected) {
		t.Fatalf("EffectiveCapabilities returned %d caps, want %d: %v", len(effective), len(expected), effective)
	}
	for _, cap := range effective {
		if !expected[cap] {
			t.Errorf("unexpected capability: %q", cap)
		}
	}
}

func TestPolicyInheritor_EffectiveCapabilities_NoPolicy(t *testing.T) {
	pi := NewPolicyInheritor()

	// No policy set for org-unknown -> fail-closed, no capabilities.
	effective := pi.EffectiveCapabilities("org-unknown", []string{"READ", "WRITE"})
	if len(effective) != 0 {
		t.Fatalf("EffectiveCapabilities should return nil for unknown child, got %v", effective)
	}
}

func TestPolicyInheritor_EffectiveCapabilities_EmptyInherited(t *testing.T) {
	pi := NewPolicyInheritor()

	policy := FederationPolicy{
		PolicyID:      "pol-2",
		ParentOrgID:   "org-parent",
		ChildOrgID:    "org-child",
		InheritedCaps: []string{}, // nothing inherited
		DeniedCaps:    nil,
		NarrowingOnly: true,
	}
	if err := pi.SetPolicy(policy); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	effective := pi.EffectiveCapabilities("org-child", []string{"READ", "WRITE", "ADMIN"})
	if len(effective) != 0 {
		t.Fatalf("EffectiveCapabilities should return nil for empty inherited, got %v", effective)
	}
}

func TestPolicyInheritor_EffectiveCapabilities_AllDenied(t *testing.T) {
	pi := NewPolicyInheritor()

	policy := FederationPolicy{
		PolicyID:      "pol-3",
		ParentOrgID:   "org-parent",
		ChildOrgID:    "org-child",
		InheritedCaps: []string{"READ", "WRITE"},
		DeniedCaps:    []string{"READ", "WRITE"}, // everything denied
		NarrowingOnly: true,
	}
	if err := pi.SetPolicy(policy); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	effective := pi.EffectiveCapabilities("org-child", []string{"READ", "WRITE"})
	if len(effective) != 0 {
		t.Fatalf("EffectiveCapabilities should return nil when all denied, got %v", effective)
	}
}

func TestPolicyInheritor_EffectiveCapabilities_ParentLacksCapability(t *testing.T) {
	pi := NewPolicyInheritor()

	policy := FederationPolicy{
		PolicyID:      "pol-4",
		ParentOrgID:   "org-parent",
		ChildOrgID:    "org-child",
		InheritedCaps: []string{"READ", "WRITE", "ADMIN"},
		NarrowingOnly: true,
	}
	if err := pi.SetPolicy(policy); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	// Parent only has READ — child can't inherit WRITE or ADMIN from intersection.
	effective := pi.EffectiveCapabilities("org-child", []string{"READ"})
	if len(effective) != 1 || effective[0] != "READ" {
		t.Fatalf("EffectiveCapabilities = %v, want [READ]", effective)
	}
}

func TestPolicyInheritor_NarrowingOnly(t *testing.T) {
	pi := NewPolicyInheritor()

	policy := FederationPolicy{
		PolicyID:      "pol-5",
		ParentOrgID:   "org-parent",
		ChildOrgID:    "org-child",
		InheritedCaps: []string{"READ"},
		NarrowingOnly: true,
	}
	if err := pi.SetPolicy(policy); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	parentCaps := []string{"READ", "WRITE"}

	// Child requests capabilities that include one the parent has and one it doesn't.
	err := pi.ValidateNarrowing("org-child", []string{"READ", "ADMIN"}, parentCaps)
	if err == nil {
		t.Fatal("ValidateNarrowing should fail when child requests cap parent lacks")
	}
	if !strings.Contains(err.Error(), "ADMIN") {
		t.Errorf("error should mention ADMIN, got: %v", err)
	}
	if !strings.Contains(err.Error(), "narrowing violation") {
		t.Errorf("error should mention narrowing violation, got: %v", err)
	}
}

func TestPolicyInheritor_NarrowingOnly_SubsetAllowed(t *testing.T) {
	pi := NewPolicyInheritor()

	policy := FederationPolicy{
		PolicyID:      "pol-6",
		ParentOrgID:   "org-parent",
		ChildOrgID:    "org-child",
		InheritedCaps: []string{"READ"},
		NarrowingOnly: true,
	}
	if err := pi.SetPolicy(policy); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	parentCaps := []string{"READ", "WRITE", "ADMIN"}

	// Child requests a subset of parent caps — should succeed.
	err := pi.ValidateNarrowing("org-child", []string{"READ", "WRITE"}, parentCaps)
	if err != nil {
		t.Fatalf("ValidateNarrowing should succeed for subset: %v", err)
	}
}

func TestPolicyInheritor_NarrowingDisabled(t *testing.T) {
	pi := NewPolicyInheritor()

	policy := FederationPolicy{
		PolicyID:      "pol-7",
		ParentOrgID:   "org-parent",
		ChildOrgID:    "org-child",
		InheritedCaps: []string{"READ"},
		NarrowingOnly: false, // expansion allowed
	}
	if err := pi.SetPolicy(policy); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	parentCaps := []string{"READ"}

	// Even though child requests ADMIN (not in parent), narrowing is disabled.
	err := pi.ValidateNarrowing("org-child", []string{"READ", "ADMIN"}, parentCaps)
	if err != nil {
		t.Fatalf("ValidateNarrowing should succeed when narrowing disabled: %v", err)
	}
}

func TestPolicyInheritor_ValidateNarrowing_NoPolicy(t *testing.T) {
	pi := NewPolicyInheritor()

	err := pi.ValidateNarrowing("org-unknown", []string{"READ"}, []string{"READ"})
	if err == nil {
		t.Fatal("ValidateNarrowing should fail for unknown child")
	}
	if !strings.Contains(err.Error(), "no policy found") {
		t.Errorf("error should mention no policy, got: %v", err)
	}
}

func TestPolicyInheritor_SetPolicy_Validation(t *testing.T) {
	pi := NewPolicyInheritor()

	tests := []struct {
		name   string
		policy FederationPolicy
	}{
		{"empty policy_id", FederationPolicy{ParentOrgID: "p", ChildOrgID: "c"}},
		{"empty parent_org_id", FederationPolicy{PolicyID: "pol", ChildOrgID: "c"}},
		{"empty child_org_id", FederationPolicy{PolicyID: "pol", ParentOrgID: "p"}},
		{"same parent and child", FederationPolicy{PolicyID: "pol", ParentOrgID: "p", ChildOrgID: "p"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := pi.SetPolicy(tt.policy); err == nil {
				t.Fatalf("SetPolicy should fail for %s", tt.name)
			}
		})
	}
}

func TestPolicyInheritor_SetPolicy_Override(t *testing.T) {
	pi := NewPolicyInheritor()

	policy1 := FederationPolicy{
		PolicyID:      "pol-1",
		ParentOrgID:   "org-parent",
		ChildOrgID:    "org-child",
		InheritedCaps: []string{"READ"},
		NarrowingOnly: true,
	}
	if err := pi.SetPolicy(policy1); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	// Override with new policy for same child.
	policy2 := FederationPolicy{
		PolicyID:      "pol-2",
		ParentOrgID:   "org-parent",
		ChildOrgID:    "org-child",
		InheritedCaps: []string{"READ", "WRITE"},
		NarrowingOnly: true,
	}
	if err := pi.SetPolicy(policy2); err != nil {
		t.Fatalf("SetPolicy override: %v", err)
	}

	effective := pi.EffectiveCapabilities("org-child", []string{"READ", "WRITE", "ADMIN"})
	if len(effective) != 2 {
		t.Fatalf("EffectiveCapabilities after override = %v, want [READ, WRITE]", effective)
	}
}
