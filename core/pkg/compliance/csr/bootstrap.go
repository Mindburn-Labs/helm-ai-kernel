package csr

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/regwatch"
)

// CreateCSRWithDefaults bootstraps a fully wired CSR with:
// 1. All default compliance sources from the 10-class spec
// 2. All default adapters from regwatch
// This is the single entrypoint for "CSR on" mode.
func CreateCSRWithDefaults(graph *jkg.Graph) (*InMemoryCSR, error) {
	reg := NewInMemoryCSR()

	// Seed all default compliance sources
	if err := SeedRegistry(reg); err != nil {
		return nil, fmt.Errorf("failed to seed CSR: %w", err)
	}

	// Wire default adapters to sources
	adapters := regwatch.CreateDefaultAdaptersAll()
	for _, adapter := range adapters {
		sourceID := adapterSourceMapping(adapter.Type())
		if sourceID != "" {
			if err := reg.RegisterAdapter(sourceID, adapter); err != nil {
				return nil, fmt.Errorf("failed to register adapter %s: %w", adapter.Type(), err)
			}
		}
	}

	return reg, nil
}

// adapterSourceMapping maps regwatch.SourceType to CSR source IDs.
// This keeps the mapping in one place rather than scattered across adapters.
func adapterSourceMapping(st regwatch.SourceType) string {
	mapping := map[regwatch.SourceType]string{
		// Class 1: Law
		regwatch.SourceEURLex:   "eu-eurlex",
		regwatch.SourceFedReg:   "us-federal-register",
		regwatch.SourceECFR:     "us-ecfr",
		regwatch.SourceLegGovUK: "uk-legislation",
		regwatch.SourceSGSSO:    "sg-sso",
		regwatch.SourceCNNPC:    "cn-npc-lawdb",
		// Class 2: Privacy
		regwatch.SourceEDPB:  "eu-edpb",
		regwatch.SourceCNIL:  "fr-cnil",
		regwatch.SourceUKICO: "uk-ico",
		regwatch.SourceCPPA:  "us-ca-cppa",
		regwatch.SourceCAC:   "cn-cac",
		regwatch.SourcePIPL:  "cn-cac", // PIPL adapter maps to CAC source
		regwatch.SourceLGPD:  "br-lgpd",
		regwatch.SourcePDPA:  "sg-pdpa",
		regwatch.SourceAPPI:  "jp-appi",
		// Class 3: AI
		regwatch.SourceEUAIAct:   "eu-ai-act",
		regwatch.SourceNISTAIRMF: "us-nist-ai-rmf",
		regwatch.SourceOECDAI:    "global-oecd-ai",
		// Class 4: Sanctions
		regwatch.SourceUNSCSL:      "un-scsl",
		regwatch.SourceOFAC:        "us-ofac-sdn",
		regwatch.SourceEUSanctions: "eu-sanctions",
		regwatch.SourceUKSanctions: "uk-sanctions",
		regwatch.SourceBIS:         "us-bis-entity-list",
		regwatch.SourceCSLTrade:    "us-csl-trade",
		regwatch.SourceFATF:        "global-fatf",
		regwatch.SourceWorldBank:   "global-worldbank-debarred",
		// Class 5: Security
		regwatch.SourceNISTCSF:    "us-nist-csf",
		regwatch.SourceNIST80053:  "us-nist-800-53",
		regwatch.SourcePCIDSS:     "global-pci-dss",
		regwatch.SourceCIS:        "global-cis-controls",
		regwatch.SourceISO27001MI: "global-iso-27001",
		// Class 6: Resilience
		regwatch.SourceNIS2:  "eu-nis2",
		regwatch.SourceDORA:  "eu-dora",
		regwatch.SourceHIPAA: "us-hipaa",
		// Class 7: Identity
		regwatch.SourceeIDAS:    "eu-eidas",
		regwatch.SourceLOTL:     "eu-lotl",
		regwatch.SourceCABForum: "global-cab-forum",
		regwatch.SourceCTLog:    "global-ct-chrome",
		regwatch.SourceCTApple:  "global-ct-apple",
		regwatch.SourceETSI:     "global-etsi",
		// Class 8: Supply Chain
		regwatch.SourceCISAKEV: "us-cisa-kev",
		regwatch.SourceNVD:     "global-nvd",
		regwatch.SourceOSV:     "global-osv",
		regwatch.SourceRekor:   "global-rekor",
		// Class 9: Certification
		regwatch.SourceFedRAMP: "us-fedramp",
		regwatch.SourceCSASTAR: "global-csa-star",
		// Class 10: Entity
		regwatch.SourceGLEIF:    "global-gleif",
		regwatch.SourceUKCH:     "uk-companies-house",
		regwatch.SourceSECEDGAR: "us-sec-edgar",
		regwatch.SourceSECXBRL:  "us-sec-edgar-xbrl",
	}

	return mapping[st]
}
