package capabilities

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMissingOrgansReport_ByteForByteReproducibility(t *testing.T) {
	// This test verifies that identical inputs produce identical outputs
	// This is the core P0.2 requirement for determinism

	catalog := NewToolCatalog()
	// Register only some capabilities, leaving gaps

	detector := NewOrganDetector(catalog)

	rs := &prg.RequirementSet{
		ID: "reproducibility-test",
		Requirements: []prg.Requirement{
			{Description: "REQ_CAP: email-sender"},
			{Description: "REQ_CAP: payment-processor"},
			{Description: "REQ_CAP: unknown-capability"},
		},
	}

	// Run analysis twice
	report1 := detector.Analyze(rs)
	report2 := detector.Analyze(rs)

	// Must produce identical hashes
	assert.Equal(t, report1.ReportHash, report2.ReportHash,
		"Same input must produce same hash (byte-for-byte reproducibility)")
	assert.NotEmpty(t, report1.ReportHash, "Report hash must be computed")

	// Verify statistics match
	assert.Equal(t, report1.TotalGaps, report2.TotalGaps)
	assert.Equal(t, report1.ResolvableCount, report2.ResolvableCount)
	assert.Equal(t, report1.UnresolvableCount, report2.UnresolvableCount)
}

func TestMissingOrgansReport_DifferentOrderSameHash(t *testing.T) {
	// Different input order must still produce the same hash
	// (thanks to deterministic sorting)

	catalog := NewToolCatalog()
	detector := NewOrganDetector(catalog)

	rs1 := &prg.RequirementSet{
		ID: "order-test-1",
		Requirements: []prg.Requirement{
			{Description: "REQ_CAP: zebra-cap"},
			{Description: "REQ_CAP: alpha-cap"},
			{Description: "REQ_CAP: beta-cap"},
		},
	}

	rs2 := &prg.RequirementSet{
		ID: "order-test-1", // Same ID
		Requirements: []prg.Requirement{
			{Description: "REQ_CAP: alpha-cap"},
			{Description: "REQ_CAP: beta-cap"},
			{Description: "REQ_CAP: zebra-cap"},
		},
	}

	report1 := detector.Analyze(rs1)
	report2 := detector.Analyze(rs2)

	// Must produce identical hashes regardless of input order
	assert.Equal(t, report1.ReportHash, report2.ReportHash,
		"Different input order must produce same hash")

	// Organs should be sorted alphabetically
	assert.Equal(t, "alpha-cap", report1.MissingOrgans[0].CapabilityID)
	assert.Equal(t, "beta-cap", report1.MissingOrgans[1].CapabilityID)
	assert.Equal(t, "zebra-cap", report1.MissingOrgans[2].CapabilityID)
}

func TestMissingOrgan_EnhancedFields(t *testing.T) {
	catalog := NewToolCatalog()
	detector := NewOrganDetector(catalog)

	rs := &prg.RequirementSet{
		ID: "enhanced-test",
		Requirements: []prg.Requirement{
			{Description: "REQ_CAP: email-sender"},
		},
	}

	report := detector.Analyze(rs)
	require.Len(t, report.MissingOrgans, 1)

	organ := report.MissingOrgans[0]

	t.Run("capability_id is set", func(t *testing.T) {
		assert.Equal(t, "email-sender", organ.CapabilityID)
	})

	t.Run("required_evidence_class is inferred", func(t *testing.T) {
		assert.Contains(t, organ.RequiredEvidenceClass, "delivery_receipt")
	})

	t.Run("suggested_modules is populated from registry", func(t *testing.T) {
		require.NotEmpty(t, organ.SuggestedModules)
		assert.Equal(t, "smtp-adapter", organ.SuggestedModules[0].ModuleID)
		assert.Equal(t, 1, organ.SuggestedModules[0].Priority)
	})

	t.Run("genome_delta_proposals is generated", func(t *testing.T) {
		require.NotEmpty(t, organ.GenomeDeltaProposals)
		delta := organ.GenomeDeltaProposals[0]
		assert.Equal(t, "bind", delta.Operation)
		assert.Contains(t, delta.TargetPath, "email-sender")
		assert.NotEmpty(t, delta.ContentHash)
	})

	t.Run("resolvability is ResolvableNow for known capabilities", func(t *testing.T) {
		assert.Equal(t, ResolvableNow, organ.Resolvability)
	})
}

func TestMissingOrgan_UnknownCapability(t *testing.T) {
	catalog := NewToolCatalog()
	detector := NewOrganDetector(catalog)

	rs := &prg.RequirementSet{
		ID: "unknown-test",
		Requirements: []prg.Requirement{
			{Description: "REQ_CAP: completely-unknown-capability"},
		},
	}

	report := detector.Analyze(rs)
	require.Len(t, report.MissingOrgans, 1)

	organ := report.MissingOrgans[0]

	t.Run("resolvability is RequiresNewPack for unknown", func(t *testing.T) {
		assert.Equal(t, RequiresNewPack, organ.Resolvability)
	})

	t.Run("suggested_modules is empty", func(t *testing.T) {
		assert.Empty(t, organ.SuggestedModules)
	})

	t.Run("delta proposal suggests pack install", func(t *testing.T) {
		require.NotEmpty(t, organ.GenomeDeltaProposals)
		delta := organ.GenomeDeltaProposals[0]
		assert.Equal(t, "add", delta.Operation)
		assert.Contains(t, delta.TargetPath, "required_packs")
	})

	t.Run("report counts are correct", func(t *testing.T) {
		assert.Equal(t, 1, report.TotalGaps)
		assert.Equal(t, 0, report.ResolvableCount)
		assert.Equal(t, 1, report.UnresolvableCount)
	})
}

func TestMissingOrgan_EvidenceClassInference(t *testing.T) {
	catalog := NewToolCatalog()
	detector := NewOrganDetector(catalog)

	testCases := []struct {
		capabilityID     string
		expectedEvidence string
	}{
		{"payment-processor", "SLSA"},
		{"fund-transfer", "SLSA"},
		{"document-signer", "signature_proof"},
		{"legal-review", "signature_proof"},
		{"kyc-verifier", "compliance_evidence"},
		{"identity-verify", "compliance_evidence"},
		{"email-sender", "delivery_receipt"},
		{"push-notify", "delivery_receipt"},
		{"generic-tool", "attestation"},
	}

	for _, tc := range testCases {
		t.Run(tc.capabilityID, func(t *testing.T) {
			rs := &prg.RequirementSet{
				ID: "evidence-test",
				Requirements: []prg.Requirement{
					{Description: "REQ_CAP: " + tc.capabilityID},
				},
			}

			report := detector.Analyze(rs)
			require.Len(t, report.MissingOrgans, 1)

			assert.Contains(t, report.MissingOrgans[0].RequiredEvidenceClass, tc.expectedEvidence,
				"Capability %s should require %s evidence", tc.capabilityID, tc.expectedEvidence)
		})
	}
}

func TestDefaultModuleRegistry(t *testing.T) {
	registry := NewDefaultModuleRegistry()

	t.Run("Returns sorted modules by priority", func(t *testing.T) {
		modules := registry.GetModulesForCapability("email-sender")
		require.Len(t, modules, 2)
		assert.Equal(t, 1, modules[0].Priority)
		assert.Equal(t, 2, modules[1].Priority)
	})

	t.Run("Returns nil for unknown capability", func(t *testing.T) {
		modules := registry.GetModulesForCapability("unknown")
		assert.Nil(t, modules)
	})

	t.Run("GetPackForModule finds pack", func(t *testing.T) {
		pack := registry.GetPackForModule("stripe-adapter")
		assert.Equal(t, "finops-pack-v1", pack)
	})

	t.Run("GetPackForModule returns empty for unknown", func(t *testing.T) {
		pack := registry.GetPackForModule("unknown-module")
		assert.Empty(t, pack)
	})
}

func TestMissingOrgansReport_ComputeHash(t *testing.T) {
	report := &MissingOrgansReport{
		Context: "test-context",
		MissingOrgans: []MissingOrgan{
			{CapabilityID: "cap-b"},
			{CapabilityID: "cap-a"},
		},
	}

	hash := report.ComputeHash()
	assert.Len(t, hash, 64, "SHA-256 hex should be 64 characters")

	// Same report should produce same hash
	hash2 := report.ComputeHash()
	assert.Equal(t, hash, hash2)
}

func TestResolvabilityClassification(t *testing.T) {
	catalog := NewToolCatalog()
	detector := NewOrganDetector(catalog)

	rs := &prg.RequirementSet{
		ID: "resolvability-test",
		Requirements: []prg.Requirement{
			{Description: "REQ_CAP: email-sender"},      // Known in registry
			{Description: "REQ_CAP: payment-processor"}, // Known in registry
			{Description: "REQ_CAP: exotic-capability"}, // Unknown
		},
	}

	report := detector.Analyze(rs)

	assert.Equal(t, 3, report.TotalGaps)
	assert.Equal(t, 2, report.ResolvableCount)   // email-sender, payment-processor
	assert.Equal(t, 1, report.UnresolvableCount) // exotic-capability
}
