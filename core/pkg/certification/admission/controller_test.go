package admission

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/certification"
)

func TestController_PackAdmission_NoAttestation(t *testing.T) {
	ctrl := NewController()

	profile := &PackAdmissionProfile{
		ProfileID: "test-profile",
		Enabled:   true,
		AdmissionRequirements: AdmissionReqs{
			RequireAttestation: true,
		},
		Enforcement: Enforcement{Mode: ModeEnforce},
	}
	_ = ctrl.LoadPackProfile(profile)

	// Test with nil attestation
	result := ctrl.AdmitPack(context.Background(), "test-profile", nil, "registry.example.com")

	if result.Decision != DecisionDeny {
		t.Errorf("expected Deny, got %s", result.Decision)
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Code != "NO_ATTESTATION" {
		t.Errorf("expected NO_ATTESTATION, got %s", result.Violations[0].Code)
	}
}

func TestController_PackAdmission_ValidAttestation(t *testing.T) {
	ctrl := NewController()

	// Generate key pair
	pub, priv, _ := ed25519.GenerateKey(nil)

	// Create valid attestation
	certifier := certification.NewCertifier("builder-1", "builder", priv)
	att, _ := certifier.CreateAttestation(
		certification.ModuleIdentity{
			ModuleID:     "mod-1",
			ArtifactHash: "sha256:abc123",
			ManifestHash: "sha256:def456",
		},
		certification.BuildProvenance{
			BuilderID:      "ci-system",
			BuildTimestamp: time.Now(),
			Reproducible:   true,
		},
		certification.CertificationResults{
			SchemaConformance: certification.ConformanceResult{Passed: true},
			DeterminismTests:  certification.DeterminismTestResult{Passed: true, TestCount: 10},
		},
	)
	_ = certifier.Sign(att)

	ctrl.RegisterPublicKey("builder-1", pub)

	profile := &PackAdmissionProfile{
		ProfileID: "test-profile",
		Enabled:   true,
		AdmissionRequirements: AdmissionReqs{
			RequireAttestation:     true,
			RequireValidSignatures: true,
		},
		Enforcement: Enforcement{Mode: ModeEnforce},
	}
	_ = ctrl.LoadPackProfile(profile)

	result := ctrl.AdmitPack(context.Background(), "test-profile", att, "registry.example.com")

	if result.Decision != DecisionAllow {
		t.Errorf("expected Allow, got %s with violations: %+v", result.Decision, result.Violations)
	}
}

func TestController_PackAdmission_MinimumSigners(t *testing.T) {
	ctrl := NewController()

	_, priv, _ := ed25519.GenerateKey(nil)
	certifier := certification.NewCertifier("builder-1", "builder", priv)
	att, _ := certifier.CreateAttestation(
		certification.ModuleIdentity{ModuleID: "mod-1", ArtifactHash: "sha256:abc", ManifestHash: "sha256:def"},
		certification.BuildProvenance{BuilderID: "ci"},
		certification.CertificationResults{},
	)
	_ = certifier.Sign(att)

	profile := &PackAdmissionProfile{
		ProfileID: "test-profile",
		Enabled:   true,
		AdmissionRequirements: AdmissionReqs{
			MinimumSigners: 2, // Requires 2 signers
		},
		Enforcement: Enforcement{Mode: ModeEnforce},
	}
	_ = ctrl.LoadPackProfile(profile)

	result := ctrl.AdmitPack(context.Background(), "test-profile", att, "registry.example.com")

	if result.Decision != DecisionDeny {
		t.Errorf("expected Deny, got %s", result.Decision)
	}

	found := false
	for _, v := range result.Violations {
		if v.Code == "INSUFFICIENT_SIGNERS" {
			found = true
		}
	}
	if !found {
		t.Error("expected INSUFFICIENT_SIGNERS violation")
	}
}

func TestController_PackAdmission_RequiredRoles(t *testing.T) {
	ctrl := NewController()

	_, priv, _ := ed25519.GenerateKey(nil)
	certifier := certification.NewCertifier("builder-1", "builder", priv)
	att, _ := certifier.CreateAttestation(
		certification.ModuleIdentity{ModuleID: "mod-1", ArtifactHash: "sha256:abc", ManifestHash: "sha256:def"},
		certification.BuildProvenance{BuilderID: "ci"},
		certification.CertificationResults{},
	)
	_ = certifier.Sign(att) // Only builder signature

	profile := &PackAdmissionProfile{
		ProfileID: "test-profile",
		Enabled:   true,
		AdmissionRequirements: AdmissionReqs{
			RequiredSignerRoles: []string{"builder", "auditor"}, // Requires auditor too
		},
		Enforcement: Enforcement{Mode: ModeEnforce},
	}
	_ = ctrl.LoadPackProfile(profile)

	result := ctrl.AdmitPack(context.Background(), "test-profile", att, "registry.example.com")

	if result.Decision != DecisionDeny {
		t.Errorf("expected Deny, got %s", result.Decision)
	}

	found := false
	for _, v := range result.Violations {
		if v.Code == "MISSING_SIGNER_ROLE" {
			found = true
		}
	}
	if !found {
		t.Error("expected MISSING_SIGNER_ROLE violation")
	}
}

func TestController_PackAdmission_RegistryDenylist(t *testing.T) {
	ctrl := NewController()

	_, priv, _ := ed25519.GenerateKey(nil)
	certifier := certification.NewCertifier("builder-1", "builder", priv)
	att, _ := certifier.CreateAttestation(
		certification.ModuleIdentity{ModuleID: "mod-1", ArtifactHash: "sha256:abc", ManifestHash: "sha256:def"},
		certification.BuildProvenance{BuilderID: "ci"},
		certification.CertificationResults{},
	)

	profile := &PackAdmissionProfile{
		ProfileID: "test-profile",
		Enabled:   true,
		AdmissionRequirements: AdmissionReqs{
			DeniedRegistries: []string{"untrusted.io"},
		},
		Enforcement: Enforcement{Mode: ModeEnforce},
	}
	_ = ctrl.LoadPackProfile(profile)

	result := ctrl.AdmitPack(context.Background(), "test-profile", att, "untrusted.io")

	if result.Decision != DecisionDeny {
		t.Errorf("expected Deny, got %s", result.Decision)
	}
}

func TestController_PackAdmission_AuditMode(t *testing.T) {
	ctrl := NewController()

	profile := &PackAdmissionProfile{
		ProfileID: "test-profile",
		Enabled:   true,
		AdmissionRequirements: AdmissionReqs{
			RequireAttestation: true,
		},
		Enforcement: Enforcement{Mode: ModeAudit}, // Audit mode
	}
	_ = ctrl.LoadPackProfile(profile)

	// Even with no attestation, should allow in audit mode
	result := ctrl.AdmitPack(context.Background(), "test-profile", nil, "registry.example.com")

	if result.Decision == DecisionDeny {
		t.Errorf("expected non-Deny in audit mode, got %s", result.Decision)
	}
	if !result.AuditOnly {
		t.Error("expected AuditOnly to be true")
	}
	if len(result.Violations) == 0 {
		t.Error("expected violations to still be recorded in audit mode")
	}
}

func TestController_DeployAdmission_FASScore(t *testing.T) {
	ctrl := NewController()

	_, priv, _ := ed25519.GenerateKey(nil)
	certifier := certification.NewCertifier("builder-1", "builder", priv)
	att, _ := certifier.CreateAttestation(
		certification.ModuleIdentity{ModuleID: "mod-1", ArtifactHash: "sha256:abc", ManifestHash: "sha256:def"},
		certification.BuildProvenance{BuilderID: "ci"},
		certification.CertificationResults{},
	)

	profile := &DeployAdmissionProfile{
		ProfileID:    "deploy-prod",
		Enabled:      true,
		Environments: []string{"production"},
		EnvironmentRequirements: EnvReqs{
			RequirePackAttestation: true,
		},
		PreDeployChecks: &PreDeployChecks{
			RequireFAS100: true,
		},
		Enforcement: Enforcement{Mode: ModeEnforce},
	}
	_ = ctrl.LoadDeployProfile(profile)

	// FAS score of 85 should fail
	result := ctrl.AdmitDeploy(context.Background(), "deploy-prod", att, "production", 85, 2)

	if result.Decision != DecisionDeny {
		t.Errorf("expected Deny, got %s", result.Decision)
	}

	found := false
	for _, v := range result.Violations {
		if v.Code == "FAS_BELOW_100" {
			found = true
		}
	}
	if !found {
		t.Error("expected FAS_BELOW_100 violation")
	}
}

func TestController_DeployAdmission_Approvals(t *testing.T) {
	ctrl := NewController()

	_, priv, _ := ed25519.GenerateKey(nil)
	certifier := certification.NewCertifier("builder-1", "builder", priv)
	att, _ := certifier.CreateAttestation(
		certification.ModuleIdentity{ModuleID: "mod-1", ArtifactHash: "sha256:abc", ManifestHash: "sha256:def"},
		certification.BuildProvenance{BuilderID: "ci"},
		certification.CertificationResults{},
	)

	profile := &DeployAdmissionProfile{
		ProfileID:               "deploy-prod",
		Enabled:                 true,
		EnvironmentRequirements: EnvReqs{},
		ApprovalChain: &ApprovalChain{
			RequiredApprovers: 2,
		},
		Enforcement: Enforcement{Mode: ModeEnforce},
	}
	_ = ctrl.LoadDeployProfile(profile)

	// Only 1 approval when 2 required
	result := ctrl.AdmitDeploy(context.Background(), "deploy-prod", att, "production", 100, 1)

	if result.Decision != DecisionDeny {
		t.Errorf("expected Deny, got %s", result.Decision)
	}

	found := false
	for _, v := range result.Violations {
		if v.Code == "INSUFFICIENT_APPROVALS" {
			found = true
		}
	}
	if !found {
		t.Error("expected INSUFFICIENT_APPROVALS violation")
	}
}

func TestController_ViolationHandler(t *testing.T) {
	ctrl := NewController()

	var captured AdmissionResult
	ctrl.AddViolationHandler(func(ctx context.Context, result AdmissionResult) {
		captured = result
	})

	profile := &PackAdmissionProfile{
		ProfileID: "test-profile",
		Enabled:   true,
		AdmissionRequirements: AdmissionReqs{
			RequireAttestation: true,
		},
		Enforcement: Enforcement{Mode: ModeEnforce},
	}
	_ = ctrl.LoadPackProfile(profile)

	ctrl.AdmitPack(context.Background(), "test-profile", nil, "registry.example.com")

	if len(captured.Violations) == 0 {
		t.Error("expected violation handler to be called with violations")
	}
}
