package gates

import (
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
)

func TestG9JurisdictionRegulatedHealthRequiresRegionalPrivacyProfile(t *testing.T) {
	evidenceDir := t.TempDir()
	setupJurisdictionEvidence(t, evidenceDir)
	result := (&G9Jurisdiction{}).Run(&conform.RunContext{
		Profile:     conform.ProfileRegulatedHealth,
		EvidenceDir: evidenceDir,
		ProjectRoot: t.TempDir(),
	})

	if result.Pass {
		t.Fatal("regulated health passed without a jurisdiction profile")
	}
	for _, want := range []string{
		conform.ReasonPrivacyErasureRequired,
		conform.ReasonRetentionPolicyMissing,
		conform.ReasonTapeResidencyViolation,
	} {
		if !reasonContains(result.Reasons, want) {
			t.Fatalf("missing reason %q in %v", want, result.Reasons)
		}
	}
}

func TestG9JurisdictionRegulatedHealthRejectsIncompleteRegionalPrivacyProfile(t *testing.T) {
	evidenceDir := t.TempDir()
	projectRoot := t.TempDir()
	setupJurisdictionEvidence(t, evidenceDir)
	writeRegionalPrivacyProfile(t, projectRoot, `
name: "European Union"
code: "eu"
data_residency: "eu-west-1"
retention:
  max_days: 365
  audit_log_days: 1825
`)

	result := (&G9Jurisdiction{}).Run(&conform.RunContext{
		Profile:      conform.ProfileRegulatedHealth,
		Jurisdiction: "EU",
		EvidenceDir:  evidenceDir,
		ProjectRoot:  projectRoot,
	})
	if result.Pass || !reasonContains(result.Reasons, conform.ReasonPrivacyErasureRequired) ||
		!reasonContains(result.Reasons, conform.ReasonRetentionPolicyMissing) {
		t.Fatalf("incomplete privacy profile result = %+v", result)
	}
	if reasonContains(result.Reasons, conform.ReasonTapeResidencyViolation) {
		t.Fatalf("configured residency was rejected: %v", result.Reasons)
	}
}

func TestG9JurisdictionRegulatedHealthAcceptsStrictRegionalPrivacyProfile(t *testing.T) {
	evidenceDir := t.TempDir()
	projectRoot := t.TempDir()
	setupJurisdictionEvidence(t, evidenceDir)
	writeRegionalPrivacyProfile(t, projectRoot, `
name: "European Union"
code: "eu"
data_residency: "eu-west-1"
right_to_erasure: true
retention:
  max_days: 365
  audit_log_days: 1825
  pii_retention_days: 30
  right_to_erasure: true
`)

	result := (&G9Jurisdiction{}).Run(&conform.RunContext{
		Profile:      conform.ProfileRegulatedHealth,
		Jurisdiction: "EU",
		EvidenceDir:  evidenceDir,
		ProjectRoot:  projectRoot,
	})
	if !result.Pass {
		t.Fatalf("strict regional privacy profile failed: %v", result.Reasons)
	}
}

func writeRegionalPrivacyProfile(t *testing.T, projectRoot, raw string) {
	t.Helper()
	path := filepath.Join(projectRoot, "core", "pkg", "config", "profiles", "profile_eu.yaml")
	mkdirGate(t, filepath.Dir(path))
	writeGateFile(t, path, []byte(raw))
}
