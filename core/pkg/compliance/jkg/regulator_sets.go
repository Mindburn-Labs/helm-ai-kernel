package jkg

// RegulatorSet is a named group of regulators for a given obligation domain.
// This avoids hardcoding 100+ DPAs individually; instead, CSR treats
// "a directory of authorities" as a source.
type RegulatorSet struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Domain      string        `json:"domain"` // e.g., "privacy", "sanctions", "financial"
	Regulators  []RegulatorID `json:"regulators"`
}

// Pre-defined regulator sets for global CSR coverage.
var (
	// EUGDPRDPASet contains EU/EEA data protection authorities.
	EUGDPRDPASet = &RegulatorSet{
		Name:        "EU_GDPR_DPA_SET",
		Description: "EU/EEA Data Protection Authorities under GDPR",
		Domain:      "privacy",
		Regulators: []RegulatorID{
			RegulatorEDPB,
			RegulatorCNIL,
			// Directory-driven: in production, this is populated from
			// the EDPB member directory, not hardcoded per-DPA.
		},
	}

	// USStatePrivacySet contains US state privacy regulators.
	USStatePrivacySet = &RegulatorSet{
		Name:        "US_STATE_PRIVACY_SET",
		Description: "US state privacy law enforcement authorities",
		Domain:      "privacy",
		Regulators:  []RegulatorID{
			// State AGs and privacy offices; populated dynamically
		},
	}

	// GlobalSanctionsAuthorities contains sanctions list publishers.
	GlobalSanctionsAuthorities = &RegulatorSet{
		Name:        "GLOBAL_SANCTIONS_AUTHORITIES",
		Description: "Global sanctions list publishers and enforcement bodies",
		Domain:      "sanctions",
		Regulators: []RegulatorID{
			RegulatorOFAC,
			RegulatorUNSC,
			RegulatorOFSI,
			RegulatorFATF,
			RegulatorBIS,
		},
	}

	// GlobalSecurityFrameworks contains security standard bodies.
	GlobalSecurityFrameworks = &RegulatorSet{
		Name:        "GLOBAL_SECURITY_FRAMEWORKS",
		Description: "Security control framework publishers",
		Domain:      "security",
		Regulators: []RegulatorID{
			RegulatorNIST,
			RegulatorCISA,
			RegulatorENISA,
		},
	}

	// GlobalEntityRegistries contains entity identity infrastructure.
	GlobalEntityRegistries = &RegulatorSet{
		Name:        "GLOBAL_ENTITY_REGISTRIES",
		Description: "Legal entity identification and registry authorities",
		Domain:      "entity",
		Regulators: []RegulatorID{
			RegulatorGLEIF,
			RegulatorCompHouse,
			RegulatorSEC,
		},
	}
)

// AllRegulatorSets returns all pre-defined regulator sets.
func AllRegulatorSets() []*RegulatorSet {
	return []*RegulatorSet{
		EUGDPRDPASet,
		USStatePrivacySet,
		GlobalSanctionsAuthorities,
		GlobalSecurityFrameworks,
		GlobalEntityRegistries,
	}
}
