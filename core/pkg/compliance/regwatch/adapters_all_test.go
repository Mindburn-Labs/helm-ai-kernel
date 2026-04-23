package regwatch

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// TestAllAdaptersCreation verifies that CreateDefaultAdaptersAll returns
// the expected number of adapters and all have valid metadata.
func TestAllAdaptersCreation(t *testing.T) {
	adapters := CreateDefaultAdaptersAll()

	// We expect 30+ adapters across 10 classes + 3 legacy
	if len(adapters) < 30 {
		t.Errorf("expected at least 30 adapters, got %d", len(adapters))
	}

	seenTypes := make(map[SourceType]bool)
	for _, a := range adapters {
		if a.Type() == "" {
			t.Error("adapter has empty SourceType")
		}
		if a.Jurisdiction() == "" {
			t.Error("adapter has empty jurisdiction")
		}
		seenTypes[a.Type()] = true
	}

	// Key types that must be present
	required := []SourceType{
		SourceEURLex, SourceFedReg, SourceLegGovUK, SourceECFR,
		SourceEDPB, SourcePIPL, SourceNISTAIRMF,
		SourceUNSCSL, SourceOFAC, SourceNISTCSF,
		SourceNIS2, SourceeIDAS, SourceCISAKEV,
		SourceFedRAMP, SourceGLEIF,
	}
	for _, st := range required {
		if !seenTypes[st] {
			t.Errorf("missing required adapter type: %s", st)
		}
	}
}

// TestLawAdapters verifies all Class 1 (Law) adapters.
func TestLawAdapters(t *testing.T) {
	tests := []struct {
		name         string
		adapter      SourceAdapter
		expectedType SourceType
		jurisdiction jkg.JurisdictionCode
	}{
		{"EURLex", NewEURLexAdapter([]string{"MiCA"}), SourceEURLex, jkg.JurisdictionEU},
		{"FederalRegister", NewFederalRegisterAdapter(), SourceFedReg, jkg.JurisdictionUS},
		{"LegislationGovUK", NewLegislationGovUKAdapter(), SourceLegGovUK, jkg.JurisdictionGB},
		{"eCFR", NewECFRAdapter([]int{12, 17}), SourceECFR, jkg.JurisdictionUS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertAdapterMeta(t, tt.adapter, tt.expectedType, tt.jurisdiction)
			assertFetchEmpty(t, tt.adapter)
			assertHealthy(t, tt.adapter)
		})
	}
}

// TestPrivacyAdapters verifies all Class 2 (Privacy) adapters.
func TestPrivacyAdapters(t *testing.T) {
	tests := []struct {
		name         string
		adapter      SourceAdapter
		expectedType SourceType
		jurisdiction jkg.JurisdictionCode
	}{
		{"EDPB", NewEDPBAdapter(), SourceEDPB, jkg.JurisdictionEU},
		{"PIPL", NewPIPLAdapter(), SourcePIPL, jkg.JurisdictionCN},
		{"LGPD", NewLGPDAdapter(), SourceLGPD, jkg.JurisdictionBR},
		{"PDPA", NewPDPAAdapter(), SourcePDPA, jkg.JurisdictionSG},
		{"APPI", NewAPPIAdapter(), SourceAPPI, jkg.JurisdictionJP},
		{"UKICO", NewUKICOAdapter(), SourceUKICO, jkg.JurisdictionGB},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertAdapterMeta(t, tt.adapter, tt.expectedType, tt.jurisdiction)
			assertFetchEmpty(t, tt.adapter)
			assertHealthy(t, tt.adapter)
		})
	}
}

// TestAIGovernanceAdapters verifies all Class 3 (AI Governance) adapters.
func TestAIGovernanceAdapters(t *testing.T) {
	tests := []struct {
		name         string
		adapter      SourceAdapter
		expectedType SourceType
		jurisdiction jkg.JurisdictionCode
	}{
		{"NIST_AI_RMF", NewNISTAIRMFAdapter(), SourceNISTAIRMF, jkg.JurisdictionGlobal},
		{"EU_AI_Act", NewEUAIActAdapter(), SourceEUAIAct, jkg.JurisdictionEU},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertAdapterMeta(t, tt.adapter, tt.expectedType, tt.jurisdiction)
			assertFetchEmpty(t, tt.adapter)
			assertHealthy(t, tt.adapter)
		})
	}
}

// TestSanctionsAdapters verifies all Class 4 (Sanctions/AML) adapters.
func TestSanctionsAdapters(t *testing.T) {
	tests := []struct {
		name         string
		adapter      SourceAdapter
		expectedType SourceType
		jurisdiction jkg.JurisdictionCode
	}{
		{"UN_Sanctions", NewUNSanctionsAdapter(), SourceUNSCSL, jkg.JurisdictionGlobal},
		{"OFAC", NewOFACAdapter(), SourceOFAC, jkg.JurisdictionUS},
		{"EU_Sanctions", NewEUSanctionsAdapter(), SourceEUSanctions, jkg.JurisdictionEU},
		{"UK_Sanctions", NewUKSanctionsAdapter(), SourceUKSanctions, jkg.JurisdictionGB},
		{"FATF", NewFATFAdapter(), SourceFATF, jkg.JurisdictionGlobal},
		{"BIS_Entity", NewBISEntityListAdapter(), SourceBIS, jkg.JurisdictionUS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertAdapterMeta(t, tt.adapter, tt.expectedType, tt.jurisdiction)
			assertFetchEmpty(t, tt.adapter)
			assertHealthy(t, tt.adapter)
		})
	}
}

// TestSecurityAdapters verifies all Class 5 (Security Controls) adapters.
func TestSecurityAdapters(t *testing.T) {
	tests := []struct {
		name         string
		adapter      SourceAdapter
		expectedType SourceType
		jurisdiction jkg.JurisdictionCode
	}{
		{"NIST_CSF", NewNISTCSFAdapter(), SourceNISTCSF, jkg.JurisdictionGlobal},
		{"NIST_800-53", NewNIST80053Adapter(), SourceNIST80053, jkg.JurisdictionGlobal},
		{"PCI_DSS", NewPCIDSSAdapter(), SourcePCIDSS, jkg.JurisdictionGlobal},
		{"ISO_27001", NewISO27001ManualImportAdapter("ISO/IEC 27001:2022", ""), SourceISO27001MI, jkg.JurisdictionGlobal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertAdapterMeta(t, tt.adapter, tt.expectedType, tt.jurisdiction)
			assertFetchEmpty(t, tt.adapter)
			assertHealthy(t, tt.adapter)
		})
	}
}

// TestResilienceAdapters verifies all Class 6 (Resilience) adapters.
func TestResilienceAdapters(t *testing.T) {
	tests := []struct {
		name         string
		adapter      SourceAdapter
		expectedType SourceType
		jurisdiction jkg.JurisdictionCode
	}{
		{"NIS2", NewNIS2Adapter(), SourceNIS2, jkg.JurisdictionEU},
		{"DORA", NewDORAAdapter(), SourceDORA, jkg.JurisdictionEU},
		{"HIPAA", NewHIPAAAdapter(), SourceHIPAA, jkg.JurisdictionUS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertAdapterMeta(t, tt.adapter, tt.expectedType, tt.jurisdiction)
			assertFetchEmpty(t, tt.adapter)
			assertHealthy(t, tt.adapter)
		})
	}
}

// TestIdentityAdapters verifies all Class 7 (Identity/Trust) adapters.
func TestIdentityAdapters(t *testing.T) {
	tests := []struct {
		name         string
		adapter      SourceAdapter
		expectedType SourceType
		jurisdiction jkg.JurisdictionCode
	}{
		{"eIDAS", NewEIDASAdapter(), SourceeIDAS, jkg.JurisdictionEU},
		{"LOTL", NewLOTLAdapter(), SourceLOTL, jkg.JurisdictionEU},
		{"CABForum", NewCABForumAdapter(), SourceCABForum, jkg.JurisdictionGlobal},
		{"CTLog", NewCTLogAdapter(), SourceCTLog, jkg.JurisdictionGlobal},
		{"ETSI", NewETSISignatureStandardsAdapter(), SourceETSI, jkg.JurisdictionEU},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertAdapterMeta(t, tt.adapter, tt.expectedType, tt.jurisdiction)
			assertFetchEmpty(t, tt.adapter)
			assertHealthy(t, tt.adapter)
		})
	}
}

// TestSupplyChainAdapters verifies all Class 8 (Supply Chain) adapters.
func TestSupplyChainAdapters(t *testing.T) {
	tests := []struct {
		name         string
		adapter      SourceAdapter
		expectedType SourceType
		jurisdiction jkg.JurisdictionCode
	}{
		{"CISA_KEV", NewCISAKEVAdapter(), SourceCISAKEV, jkg.JurisdictionUS},
		{"NVD", NewNVDAdapter(), SourceNVD, jkg.JurisdictionGlobal},
		{"OSV", NewOSVAdapter(), SourceOSV, jkg.JurisdictionGlobal},
		{"Rekor", NewSigstoreRekorAdapter(), SourceRekor, jkg.JurisdictionGlobal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertAdapterMeta(t, tt.adapter, tt.expectedType, tt.jurisdiction)
			assertFetchEmpty(t, tt.adapter)
			assertHealthy(t, tt.adapter)
		})
	}
}

// TestCertificationAdapters verifies all Class 9 (Certification) adapters.
func TestCertificationAdapters(t *testing.T) {
	tests := []struct {
		name         string
		adapter      SourceAdapter
		expectedType SourceType
		jurisdiction jkg.JurisdictionCode
	}{
		{"FedRAMP", NewFedRAMPAdapter(), SourceFedRAMP, jkg.JurisdictionUS},
		{"CSA_STAR", NewCSASTARAdapter(), SourceCSASTAR, jkg.JurisdictionGlobal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertAdapterMeta(t, tt.adapter, tt.expectedType, tt.jurisdiction)
			assertFetchEmpty(t, tt.adapter)
			assertHealthy(t, tt.adapter)
		})
	}
}

// TestEntityAdapters verifies all Class 10 (Entity Registry) adapters.
func TestEntityAdapters(t *testing.T) {
	tests := []struct {
		name         string
		adapter      SourceAdapter
		expectedType SourceType
		jurisdiction jkg.JurisdictionCode
	}{
		{"GLEIF", NewGLEIFAdapter(), SourceGLEIF, jkg.JurisdictionGlobal},
		{"UK_CompaniesHouse", NewUKCompaniesHouseAdapter(), SourceUKCH, jkg.JurisdictionGB},
		{"SEC_EDGAR", NewSECEDGARAdapter(), SourceSECEDGAR, jkg.JurisdictionUS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertAdapterMeta(t, tt.adapter, tt.expectedType, tt.jurisdiction)
			assertFetchEmpty(t, tt.adapter)
			assertHealthy(t, tt.adapter)
		})
	}
}

// TestBootstrapAdapterResolve verifies end-to-end adapter resolution.
func TestBootstrapAdapterResolve(t *testing.T) {
	// Ensure CreateDefaultAdaptersAll creates non-nil adapters
	adapters := CreateDefaultAdaptersAll()
	for i, a := range adapters {
		if a == nil {
			t.Fatalf("adapter at index %d is nil", i)
		}
	}
}

// ── Test Helpers ──

func assertAdapterMeta(t *testing.T, a SourceAdapter, expectedType SourceType, expectedJurisdiction jkg.JurisdictionCode) {
	t.Helper()
	if a.Type() != expectedType {
		t.Errorf("expected type %s, got %s", expectedType, a.Type())
	}
	if a.Jurisdiction() != expectedJurisdiction {
		t.Errorf("expected jurisdiction %s, got %s", expectedJurisdiction, a.Jurisdiction())
	}
}

func assertFetchEmpty(t *testing.T, a SourceAdapter) {
	t.Helper()
	ctx := context.Background()
	changes, err := a.FetchChanges(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Errorf("FetchChanges returned unexpected error: %v", err)
	}
	if changes == nil {
		t.Error("FetchChanges returned nil (should return empty slice)")
	}
}

func assertHealthy(t *testing.T, a SourceAdapter) {
	t.Helper()
	ctx := context.Background()
	if !a.IsHealthy(ctx) {
		t.Error("adapter reports unhealthy after construction")
	}
}
