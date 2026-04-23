package jkg

import "time"

// DefaultJurisdictions returns pre-configured jurisdictions.
func DefaultJurisdictions() []*Jurisdiction {
	return []*Jurisdiction{
		{
			Code:       JurisdictionEU,
			Name:       "European Union",
			Regulators: []RegulatorID{RegulatorESMA, RegulatorEBA},
			TimeZone:   "CET",
		},
		{
			Code:       JurisdictionUS,
			Name:       "United States",
			Regulators: []RegulatorID{RegulatorFinCEN, RegulatorSEC, RegulatorCFTC},
			TimeZone:   "EST",
		},
		{
			Code:       JurisdictionGB,
			Name:       "United Kingdom",
			Regulators: []RegulatorID{RegulatorFCA, RegulatorPRA},
			TimeZone:   "GMT",
		},
		{
			Code:       JurisdictionBG,
			Name:       "Bulgaria",
			Regulators: []RegulatorID{RegulatorFSC, RegulatorNRA},
			ParentCode: JurisdictionEU,
			Treaties:   []string{"EU-Single-Market", "Schengen"},
			TimeZone:   "EET",
		},
		{
			Code:       JurisdictionCY,
			Name:       "Cyprus",
			Regulators: []RegulatorID{RegulatorCySEC},
			ParentCode: JurisdictionEU,
			TimeZone:   "EET",
		},
	}
}

// DefaultRegulators returns pre-configured regulators.
func DefaultRegulators() []*Regulator {
	return []*Regulator{
		{
			ID:                RegulatorESMA,
			Name:              "European Securities and Markets Authority",
			Jurisdiction:      JurisdictionEU,
			Scope:             []string{"securities", "crypto", "markets"},
			Website:           "https://www.esma.europa.eu",
			FeedURL:           "https://www.esma.europa.eu/rss",
			EnforcementPowers: []string{"fines", "bans", "warnings"},
		},
		{
			ID:                RegulatorEBA,
			Name:              "European Banking Authority",
			Jurisdiction:      JurisdictionEU,
			Scope:             []string{"banking", "payments", "aml"},
			Website:           "https://www.eba.europa.eu",
			EnforcementPowers: []string{"guidelines", "recommendations"},
		},
		{
			ID:                RegulatorFinCEN,
			Name:              "Financial Crimes Enforcement Network",
			Jurisdiction:      JurisdictionUS,
			Scope:             []string{"aml", "kyc", "msb"},
			Website:           "https://www.fincen.gov",
			FeedURL:           "https://www.fincen.gov/rss",
			EnforcementPowers: []string{"civil_penalties", "criminal_referral"},
		},
		{
			ID:                RegulatorSEC,
			Name:              "Securities and Exchange Commission",
			Jurisdiction:      JurisdictionUS,
			Scope:             []string{"securities", "investment"},
			Website:           "https://www.sec.gov",
			EnforcementPowers: []string{"civil_penalties", "disgorgement", "bans"},
		},
		{
			ID:                RegulatorCFTC,
			Name:              "Commodity Futures Trading Commission",
			Jurisdiction:      JurisdictionUS,
			Scope:             []string{"derivatives", "commodities", "prediction_markets", "swaps"},
			Website:           "https://www.cftc.gov",
			FeedURL:           "https://www.cftc.gov/RSS/RSSData",
			EnforcementPowers: []string{"civil_penalties", "cease_and_desist", "disgorgement", "trading_bans"},
		},
		{
			ID:                RegulatorFCA,
			Name:              "Financial Conduct Authority",
			Jurisdiction:      JurisdictionGB,
			Scope:             []string{"banking", "crypto", "payments", "insurance"},
			Website:           "https://www.fca.org.uk",
			FeedURL:           "https://www.fca.org.uk/news-and-publications/rss-feeds",
			EnforcementPowers: []string{"fines", "prohibition_orders", "restitution"},
		},
		{
			ID:                RegulatorPRA,
			Name:              "Prudential Regulation Authority",
			Jurisdiction:      JurisdictionGB,
			Scope:             []string{"prudential", "banking", "insurance"},
			Website:           "https://www.bankofengland.co.uk/prudential-regulation",
			EnforcementPowers: []string{"capital_requirements", "restrictions"},
		},
		{
			ID:                RegulatorFSC,
			Name:              "Financial Supervision Commission",
			Jurisdiction:      JurisdictionBG,
			Scope:             []string{"securities", "insurance", "pensions"},
			Website:           "https://www.fsc.bg",
			EnforcementPowers: []string{"fines", "license_revocation"},
		},
		{
			ID:                RegulatorNRA,
			Name:              "National Revenue Agency",
			Jurisdiction:      JurisdictionBG,
			Scope:             []string{"tax", "reporting"},
			Website:           "https://www.nra.bg",
			EnforcementPowers: []string{"tax_penalties", "audits"},
		},
		{
			ID:                RegulatorCySEC,
			Name:              "Cyprus Securities and Exchange Commission",
			Jurisdiction:      JurisdictionCY,
			Scope:             []string{"securities", "crypto", "forex"},
			Website:           "https://www.cysec.gov.cy",
			EnforcementPowers: []string{"fines", "license_revocation", "warnings"},
		},
	}
}

// MiCAObligations returns MiCA (Markets in Crypto-Assets) obligations.
func MiCAObligations() []*Obligation {
	return []*Obligation{
		{
			ObligationID:     "MICA-CASP-AUTH",
			JurisdictionCode: JurisdictionEU,
			RegulatorID:      RegulatorESMA,
			Framework:        "MiCA",
			ArticleRef:       "Article 59",
			Type:             ObligationRegistration,
			Title:            "CASP Authorization Requirement",
			Description:      "Crypto-asset service providers must obtain authorization from competent authority",
			EffectiveFrom:    time.Date(2024, 12, 30, 0, 0, 0, 0, time.UTC),
			RiskLevel:        RiskCritical,
			PenaltyMax:       "€5M or 3% annual turnover",
			EvidenceReqs:     []string{"authorization_certificate", "compliance_program", "aml_policy"},
			SourceURL:        "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1114",
			Version:          1,
		},
		{
			ObligationID:     "MICA-WP-PUB",
			JurisdictionCode: JurisdictionEU,
			RegulatorID:      RegulatorESMA,
			Framework:        "MiCA",
			ArticleRef:       "Article 6",
			Type:             ObligationRequirement,
			Title:            "White Paper Publication",
			Description:      "Issuers must publish a white paper before offering crypto-assets",
			EffectiveFrom:    time.Date(2024, 6, 30, 0, 0, 0, 0, time.UTC),
			RiskLevel:        RiskHigh,
			PenaltyMax:       "€700K",
			EvidenceReqs:     []string{"white_paper", "publication_proof", "esma_notification"},
			SourceURL:        "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1114",
			Version:          1,
		},
		{
			ObligationID:     "MICA-ART-EMT",
			JurisdictionCode: JurisdictionEU,
			RegulatorID:      RegulatorEBA,
			Framework:        "MiCA",
			ArticleRef:       "Article 48",
			Type:             ObligationRequirement,
			Title:            "E-Money Token Requirements",
			Description:      "E-money token issuers must be authorized credit/e-money institution",
			EffectiveFrom:    time.Date(2024, 6, 30, 0, 0, 0, 0, time.UTC),
			RiskLevel:        RiskCritical,
			PenaltyMax:       "€5M or 3% annual turnover",
			EvidenceReqs:     []string{"emi_license", "reserve_attestation", "redemption_policy"},
			SourceURL:        "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1114",
			Version:          1,
		},
	}
}

// EUAIActObligations returns EU AI Act obligations.
func EUAIActObligations() []*Obligation {
	return []*Obligation{
		{
			ObligationID:     "EUAI-PROHIB-001",
			JurisdictionCode: JurisdictionEU,
			RegulatorID:      RegulatorESMA,
			Framework:        "EU AI Act",
			ArticleRef:       "Article 5",
			Type:             ObligationProhibition,
			Title:            "Prohibited AI Practices",
			Description:      "Ban on social scoring, predictive policing, emotion recognition in workplace/education",
			EffectiveFrom:    time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC),
			RiskLevel:        RiskCritical,
			PenaltyMax:       "€35M or 7% global turnover",
			EvidenceReqs:     []string{"ai_inventory", "risk_assessment", "compliance_declaration"},
			SourceURL:        "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
			Version:          1,
		},
		{
			ObligationID:     "EUAI-GPAI-001",
			JurisdictionCode: JurisdictionEU,
			RegulatorID:      RegulatorESMA,
			Framework:        "EU AI Act",
			ArticleRef:       "Article 53",
			Type:             ObligationRequirement,
			Title:            "GPAI Model Transparency",
			Description:      "General-purpose AI model providers must provide technical documentation",
			EffectiveFrom:    time.Date(2025, 8, 2, 0, 0, 0, 0, time.UTC),
			RiskLevel:        RiskHigh,
			PenaltyMax:       "€15M or 3% global turnover",
			EvidenceReqs:     []string{"model_card", "training_data_summary", "capability_assessment"},
			SourceURL:        "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
			Version:          1,
		},
	}
}

// AMLObligations returns Anti-Money Laundering obligations.
func AMLObligations() []*Obligation {
	return []*Obligation{
		{
			ObligationID:     "US-BSA-SAR",
			JurisdictionCode: JurisdictionUS,
			RegulatorID:      RegulatorFinCEN,
			Framework:        "BSA/AML",
			ArticleRef:       "31 CFR 1020.320",
			Type:             ObligationReporting,
			Title:            "Suspicious Activity Report",
			Description:      "File SAR for transactions over $5,000 that are suspicious",
			EffectiveFrom:    time.Date(1992, 1, 1, 0, 0, 0, 0, time.UTC),
			RiskLevel:        RiskCritical,
			PenaltyMax:       "$500K per violation",
			EvidenceReqs:     []string{"sar_filing", "investigation_memo", "escalation_record"},
			SourceURL:        "https://www.fincen.gov/resources/statutes-regulations/guidance",
			Version:          1,
		},
		{
			ObligationID:     "US-BSA-CTR",
			JurisdictionCode: JurisdictionUS,
			RegulatorID:      RegulatorFinCEN,
			Framework:        "BSA/AML",
			ArticleRef:       "31 CFR 1010.311",
			Type:             ObligationReporting,
			Title:            "Currency Transaction Report",
			Description:      "File CTR for cash transactions over $10,000",
			EffectiveFrom:    time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
			RiskLevel:        RiskHigh,
			PenaltyMax:       "$500K per violation",
			EvidenceReqs:     []string{"ctr_filing", "transaction_records"},
			SourceURL:        "https://www.fincen.gov/resources/statutes-regulations/guidance",
			Version:          1,
		},
		{
			ObligationID:     "EU-AMLD6-CDD",
			JurisdictionCode: JurisdictionEU,
			RegulatorID:      RegulatorEBA,
			Framework:        "AMLD6",
			ArticleRef:       "Article 13",
			Type:             ObligationRequirement,
			Title:            "Customer Due Diligence",
			Description:      "Obliged entities must apply CDD measures to customers",
			EffectiveFrom:    time.Date(2024, 12, 3, 0, 0, 0, 0, time.UTC),
			RiskLevel:        RiskCritical,
			PenaltyMax:       "€5M or 10% annual turnover",
			EvidenceReqs:     []string{"kyc_records", "risk_rating", "ongoing_monitoring"},
			SourceURL:        "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024L1640",
			Version:          1,
		},
	}
}

// NewGraphWithDefaults creates a graph pre-populated with standard data.
func NewGraphWithDefaults() *Graph {
	g := NewGraph()

	// Add jurisdictions
	for _, j := range DefaultJurisdictions() {
		_ = g.AddJurisdiction(j) //nolint:errcheck // defaults init, errors are structurally impossible
	}

	// Add regulators
	for _, r := range DefaultRegulators() {
		_ = g.AddRegulator(r) //nolint:errcheck // defaults init, errors are structurally impossible
	}

	// Add MiCA obligations
	for _, o := range MiCAObligations() {
		_ = g.AddObligation(o) //nolint:errcheck // defaults init, errors are structurally impossible
	}

	// Add EU AI Act obligations
	for _, o := range EUAIActObligations() {
		_ = g.AddObligation(o) //nolint:errcheck // defaults init, errors are structurally impossible
	}

	// Add AML obligations
	for _, o := range AMLObligations() {
		_ = g.AddObligation(o) //nolint:errcheck // defaults init, errors are structurally impossible
	}

	// Add known conflicts
	_ = g.AddEdge(&Edge{ //nolint:errcheck // defaults init, errors are structurally impossible
		Type:     EdgeConflictsWith,
		FromID:   "EU-AMLD6-CDD",
		FromType: "obligation",
		ToID:     "US-BSA-SAR",
		ToType:   "obligation",
		Properties: map[string]interface{}{
			"reason":   "Privacy vs reporting requirements",
			"severity": "medium",
		},
	})

	return g
}
