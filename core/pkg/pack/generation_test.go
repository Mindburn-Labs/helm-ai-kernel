package pack_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/pack"
)

// repoRoot returns the root of the helm-oss repository by walking up
// from this test file's location (core/pkg/pack/).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
}

// TestPackGenerationAndGrading_OpsRelease tests building, grading, and
// verifying a pack modeled after the customer-ops reference pack.
func TestPackGenerationAndGrading_OpsRelease(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	manifest := pack.PackManifest{
		PackID:        "customer-ops-v1",
		Type:          pack.PackTypeFactory,
		SchemaVersion: "1.0.0",
		Version:       "1.0.0",
		Name:          "customer-ops",
		Description:   "Governs customer follow-ups, CRM task sync, account escalation drafts",
		Capabilities:  []string{"crm-sync", "customer-followup", "escalation-draft"},
		EvidenceContract: &pack.EvidenceContract{
			Produces: []pack.EvidenceProduce{
				{Class: "execution_receipt", Format: "json", Retention: 90},
			},
			Requires: []pack.EvidenceRequire{
				{Class: "approval", Source: "human_operator"},
			},
		},
		Provenance: &pack.Provenance{
			Source: &pack.SourceInfo{
				Repo:   "github.com/mindburn-labs/helm-oss",
				Commit: "abc123",
				Tag:    "v1.0.0",
			},
		},
	}

	// Build
	builder := pack.NewPackBuilder(manifest).WithSigningKey(priv)
	p, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if p.Manifest.Name != "customer-ops" {
		t.Errorf("Expected pack name customer-ops, got %s", p.Manifest.Name)
	}
	if p.ContentHash == "" {
		t.Error("Pack content hash should not be empty")
	}
	if p.Signature == "" {
		t.Error("Pack signature should not be empty after signing")
	}
	if p.Manifest.Type != pack.PackTypeFactory {
		t.Errorf("Expected pack type factory, got %s", p.Manifest.Type)
	}

	// Grade: should reach Bronze (has signature)
	grader := pack.NewPackGrader()
	report, err := grader.Grade(context.Background(), p)
	if err != nil {
		t.Fatalf("Grading failed: %v", err)
	}
	if report.Grade != pack.GradeBronze {
		t.Errorf("Expected Bronze grade (signed, no tests), got %s", report.Grade)
	}

	// Promote to Silver by adding test evidence
	if p.Metadata == nil {
		p.Metadata = make(map[string]interface{})
	}
	p.Metadata["tested"] = true
	report, err = grader.Grade(context.Background(), p)
	if err != nil {
		t.Fatalf("Grading (Silver) failed: %v", err)
	}
	if report.Grade != pack.GradeSilver {
		t.Errorf("Expected Silver grade, got %s", report.Grade)
	}

	// Promote to Gold by adding drill evidence
	p.Metadata["drilled"] = true
	report, err = grader.Grade(context.Background(), p)
	if err != nil {
		t.Fatalf("Grading (Gold) failed: %v", err)
	}
	if report.Grade != pack.GradeGold {
		t.Errorf("Expected Gold grade, got %s", report.Grade)
	}

	// Verify manifest validation
	if err := pack.ValidateManifest(manifest); err != nil {
		t.Errorf("ValidateManifest failed: %v", err)
	}
}

// TestPackGenerationAndGrading_JurisdictionSec tests building a policy
// pack modeled after jurisdiction-scoped security packs.
func TestPackGenerationAndGrading_JurisdictionSec(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	manifest := pack.PackManifest{
		PackID:        "finance-sec-v1",
		Type:          pack.PackTypePolicy,
		SchemaVersion: "1.0.0",
		Version:       "1.0.0",
		Name:          "finance-sec",
		Description:   "Financial services security pack with jurisdiction constraints",
		Capabilities:  []string{"policy-finance", "jurisdiction-sec"},
		ApplicabilityConstraints: &pack.ApplicabilityConstraints{
			Jurisdictions: &pack.JurisdictionConstraints{
				Allowed: []string{"US", "GB", "EU"},
			},
			Industries: &pack.IndustryConstraints{
				Allowed: []string{"financial_services", "banking"},
			},
			MinAutonomy: "supervised",
		},
		EvidenceContract: &pack.EvidenceContract{
			Produces: []pack.EvidenceProduce{
				{Class: "policy_decision", Format: "json", Retention: 365},
				{Class: "audit_trail", Format: "json", Retention: 2555},
			},
			Requires: []pack.EvidenceRequire{
				{Class: "regulatory_context", Source: "jurisdiction_overlay"},
			},
		},
		PDPHooks: []pack.PDPHook{
			{HookType: "pre_decision", EffectTypes: []string{"E2", "E3", "E4"}, PolicyRef: "finance-sec/rules.cel"},
		},
	}

	// Build
	builder := pack.NewPackBuilder(manifest).WithSigningKey(priv)
	p, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if p.Manifest.Name != "finance-sec" {
		t.Errorf("Expected pack name finance-sec, got %s", p.Manifest.Name)
	}
	if p.Manifest.Type != pack.PackTypePolicy {
		t.Errorf("Expected pack type policy, got %s", p.Manifest.Type)
	}
	if p.ContentHash == "" {
		t.Error("Pack content hash should not be empty")
	}
	if p.Signature == "" {
		t.Error("Pack signature should not be empty after signing")
	}

	// Verify jurisdictions
	if p.Manifest.ApplicabilityConstraints == nil {
		t.Fatal("ApplicabilityConstraints should not be nil")
	}
	jc := p.Manifest.ApplicabilityConstraints.Jurisdictions
	if jc == nil || len(jc.Allowed) != 3 {
		t.Errorf("Expected 3 allowed jurisdictions, got %v", jc)
	}

	// Verify PDP hooks
	if len(p.Manifest.PDPHooks) != 1 {
		t.Fatalf("Expected 1 PDP hook, got %d", len(p.Manifest.PDPHooks))
	}
	if p.Manifest.PDPHooks[0].PolicyRef != "finance-sec/rules.cel" {
		t.Errorf("Unexpected PolicyRef: %s", p.Manifest.PDPHooks[0].PolicyRef)
	}

	// Grade: should reach Bronze (has signature)
	grader := pack.NewPackGrader()
	report, err := grader.Grade(context.Background(), p)
	if err != nil {
		t.Fatalf("Grading failed: %v", err)
	}
	if report.Grade != pack.GradeBronze {
		t.Errorf("Expected Bronze grade, got %s", report.Grade)
	}

	// Unsigned pack should not reach any grade
	unsignedManifest := manifest
	unsignedManifest.Name = "unsigned-sec"
	unsignedBuilder := pack.NewPackBuilder(unsignedManifest) // no signing key
	unsigned, err := unsignedBuilder.Build()
	if err != nil {
		t.Fatalf("Unsigned build failed: %v", err)
	}
	unsignedReport, err := grader.Grade(context.Background(), unsigned)
	if err != nil {
		t.Fatalf("Unsigned grading failed: %v", err)
	}
	if unsignedReport.Grade != "" {
		t.Errorf("Unsigned pack should have no grade, got %s", unsignedReport.Grade)
	}
}

// TestReferencePacks_Parseable verifies that the reference_packs at the repo
// root are valid JSON and contain expected top-level fields.
func TestReferencePacks_Parseable(t *testing.T) {
	root := repoRoot(t)
	packsDir := filepath.Join(root, "reference_packs")
	if _, err := os.Stat(packsDir); err != nil {
		t.Skipf("reference_packs directory not found at %s: %v", packsDir, err)
	}

	entries, err := os.ReadDir(packsDir)
	if err != nil {
		t.Fatalf("cannot read reference_packs: %v", err)
	}

	packCount := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		packCount++

		t.Run(entry.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(packsDir, entry.Name()))
			if err != nil {
				t.Fatalf("cannot read %s: %v", entry.Name(), err)
			}

			var raw map[string]interface{}
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatalf("%s is not valid JSON: %v", entry.Name(), err)
			}

			// Every reference pack must have pack_id and label.
			if _, ok := raw["pack_id"]; !ok {
				t.Errorf("%s missing pack_id field", entry.Name())
			}
			if _, ok := raw["label"]; !ok {
				t.Errorf("%s missing label field", entry.Name())
			}
		})
	}

	if packCount == 0 {
		t.Error("no reference pack JSON files found in reference_packs/")
	}
}
