package csr

import (
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// DefaultComplianceSources returns the canonical set of all compliance sources
// from the 10-class spec. This is the seed data for fresh installs.
func DefaultComplianceSources() []*ComplianceSource {
	now := time.Now()

	// ── Trust Presets (composable, small — EvidencePack records effective policy per fetch) ──

	trustTLSHashChain := TrustModel{
		RequireTLS: true, TLSMinVersion: "1.2",
		HashChain: "sha256+rfc8785-json", TimestampPolicy: "http-date",
	}

	trustSignedXML := TrustModel{
		RequireTLS: true, TLSMinVersion: "1.2",
		RequireSignature: true, SignatureFormat: "xmldsig",
		HashChain: "sha256+rfc8785-json", TimestampPolicy: "http-date",
	}

	trustSignedJSON := TrustModel{
		RequireTLS: true, TLSMinVersion: "1.2",
		RequireSignature: true, SignatureFormat: "vendor-json-signature",
		HashChain: "sha256+rfc8785-json", TimestampPolicy: "http-date",
	}

	trustTransparencyLog := TrustModel{
		RequireTLS: true, TLSMinVersion: "1.2",
		HashChain: "sha256+rfc8785-json", TimestampPolicy: "http-date",
		TransparencyLog: "rekor",
	}

	defaultFP := DefaultFetchPolicy()

	lawEvidence := EvidenceEmissionRules{EmitSourceVersion: true, EmitContentHash: true, EmitRetrievalTime: true, EmitAmendmentsChain: true}
	stdEvidence := EvidenceEmissionRules{EmitSourceVersion: true, EmitContentHash: true, EmitRetrievalTime: true}
	sigEvidence := EvidenceEmissionRules{EmitSourceVersion: true, EmitContentHash: true, EmitRetrievalTime: true, EmitSignatureProof: true}
	hashCD := ChangeDetector{Strategy: "hash", HashAlgorithm: "sha256", DiffMode: "full"}
	etagCD := ChangeDetector{Strategy: "etag", HashAlgorithm: "sha256", DiffMode: "incremental"}
	seqCD := ChangeDetector{Strategy: "sequence", HashAlgorithm: "sha256", DiffMode: "incremental"}

	eurLexFP := FetchPolicy{
		DomainsAllowlist: []string{"eur-lex.europa.eu", "publications.europa.eu"}, MaxBytesPerFetch: 50 * 1024 * 1024,
		TimeoutPerFetch: 30 * time.Second, UserAgent: defaultFP.UserAgent,
		RobotsPolicy: "respect", RateLimitRPS: 1, CachePolicy: "etag", RetryPolicy: defaultFP.RetryPolicy,
	}

	base := []*ComplianceSource{
		// ──────────────── Class 1: LAW ────────────────
		{
			SourceID: "eu-eurlex", Name: "EUR-Lex Cellar Knowledge Graph (SPARQL)", Description: "EU legislation via SPARQL endpoint",
			Class: ClassLaw, SourceType: "gazette", Jurisdiction: jkg.JurisdictionEU, Authority: jkg.RegulatorID("EU-OP"), Binding: BindingnessLaw,
			FetchMethod: FetchSPARQL, EndpointURL: "https://publications.europa.eu/webapi/rdf/sparql", AuthType: AuthNone,
			Notes: "Metadata graph + document relations (Cellar).", FetchPolicyConfig: eurLexFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/LegalSourceRecord.v1"},
			EvidenceRules: lawEvidence, Provenance: "Official Journal of the European Union", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "us-federal-register", Name: "US Federal Register (API v1)", Description: "Rules, proposed rules, notices, presidential documents",
			Class: ClassLaw, SourceType: "gazette", Jurisdiction: jkg.JurisdictionUS, Authority: jkg.RegulatorID("US-FEDREG"), Binding: BindingnessLaw,
			FetchMethod: FetchREST, EndpointURL: "https://www.federalregister.gov/api/v1/", AuthType: AuthNone,
			Notes: "Rules, proposed rules, notices, presidential documents.",
			FetchPolicyConfig: FetchPolicy{
				DomainsAllowlist: []string{"www.federalregister.gov"}, MaxBytesPerFetch: 50 * 1024 * 1024,
				TimeoutPerFetch: 30 * time.Second, UserAgent: defaultFP.UserAgent,
				RobotsPolicy: "respect", RateLimitRPS: 2, CachePolicy: "etag", RetryPolicy: defaultFP.RetryPolicy,
			},
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 6 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/LegalSourceRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "US Government Publishing Office", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "us-ecfr", Name: "US eCFR (API v1)", Description: "Codified federal regulations (titles/parts/sections)",
			Class: ClassLaw, SourceType: "gazette", Jurisdiction: jkg.JurisdictionUS, Authority: jkg.RegulatorID("US-ECFR"), Binding: BindingnessLaw,
			FetchMethod: FetchREST, EndpointURL: "https://www.ecfr.gov/api/v1/", AuthType: AuthNone,
			Notes: "Codified federal regulations (titles/parts/sections).", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/LegalSourceRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "US Government Publishing Office", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "uk-legislation", Name: "UK Legislation.gov.uk", Description: "Primary + secondary UK legislation",
			Class: ClassLaw, SourceType: "gazette", Jurisdiction: jkg.JurisdictionGB, Authority: jkg.RegulatorID("UK-LEG"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.legislation.gov.uk/", AuthType: AuthNone,
			Notes: "Adapter resolves JSON/XML where available.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/LegalSourceRecord.v1"},
			EvidenceRules: lawEvidence, Provenance: "The National Archives, UK", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "sg-sso", Name: "Singapore Statutes Online (SSO)", Description: "Acts and subsidiary legislation",
			Class: ClassLaw, SourceType: "gazette", Jurisdiction: jkg.JurisdictionSG, Authority: jkg.RegulatorID("SG-AGC"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://sso.agc.gov.sg/", AuthType: AuthNone,
			Notes: "Acts and subsidiary legislation browsing and retrieval.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/LegalSourceRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Attorney-General's Chambers, Singapore", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "cn-npc-lawdb", Name: "China National Database of Laws and Regulations (NPC)", Description: "Official NPC law/regulation database",
			Class: ClassLaw, SourceType: "gazette", Jurisdiction: jkg.JurisdictionCN, Authority: jkg.RegulatorID("CN-NPC"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://flk.npc.gov.cn/", AuthType: AuthNone,
			Notes: "Adapter normalizes updates + diffs.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/LegalSourceRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "National People's Congress, China", CreatedAt: now, LastUpdated: now,
		},

		// ──────────────── Class 2: PRIVACY ────────────────
		{
			SourceID: "eu-edpb", Name: "EDPB Publications", Description: "Guidelines, recommendations, opinions, statements",
			Class: ClassPrivacy, SourceType: "guidance", Jurisdiction: jkg.JurisdictionEU, Authority: jkg.RegulatorID("EU-EDPB"), Binding: BindingnessGuidance,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.edpb.europa.eu/our-work-tools/our-documents_en", AuthType: AuthNone,
			Notes: "Guidelines, recommendations, opinions, statements.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/GuidanceRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "European Data Protection Board", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "fr-cnil", Name: "France CNIL", Description: "Guidance, enforcement actions, consultations",
			Class: ClassPrivacy, SourceType: "guidance", Jurisdiction: jkg.JurisdictionCode("FR"), Authority: jkg.RegulatorID("EU-CNIL"), Binding: BindingnessGuidance,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.cnil.fr/", AuthType: AuthNone,
			Notes: "Guidance, enforcement actions, consultations.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/GuidanceRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Commission nationale de l'informatique et des libertés", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "uk-ico", Name: "UK ICO", Description: "UK GDPR guidance and enforcement",
			Class: ClassPrivacy, SourceType: "guidance", Jurisdiction: jkg.JurisdictionGB, Authority: jkg.RegulatorID("UK-ICO"), Binding: BindingnessGuidance,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://ico.org.uk/", AuthType: AuthNone,
			Notes: "Guidance, enforcement, consultation outputs.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/GuidanceRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Information Commissioner's Office, UK", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "us-ca-cppa", Name: "California CPPA Rulemaking", Description: "CCPA/CPRA regulations and updates",
			Class: ClassPrivacy, SourceType: "guidance", Jurisdiction: jkg.JurisdictionCode("US-CA"), Authority: jkg.RegulatorID("US-CA-CPPA"), Binding: BindingnessRegulation,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://cppa.ca.gov/regulations/", AuthType: AuthNone,
			Notes: "CCPA/CPRA regulations and updates.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/GuidanceRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "California Privacy Protection Agency", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "cn-cac", Name: "China CAC Privacy and Data Rules", Description: "PIPL-related measures, security assessment rules, cross-border guidance",
			Class: ClassPrivacy, SourceType: "guidance", Jurisdiction: jkg.JurisdictionCN, Authority: jkg.RegulatorID("CN-CAC"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.cac.gov.cn/", AuthType: AuthNone,
			Notes: "PIPL-related measures, security assessment rules, cross-border guidance.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/GuidanceRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Cyberspace Administration of China", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "br-lgpd", Name: "Brazil ANPD (LGPD)", Description: "Resolutions, guidance, enforcement, consultations",
			Class: ClassPrivacy, SourceType: "guidance", Jurisdiction: jkg.JurisdictionBR, Authority: jkg.RegulatorID("BR-ANPD"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.gov.br/anpd/", AuthType: AuthNone,
			Notes: "Resolutions, guidance, enforcement, consultations.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 7 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/GuidanceRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Autoridade Nacional de Proteção de Dados", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "sg-pdpa", Name: "Singapore PDPC (PDPA)", Description: "Advisory guidelines, decisions, breach guidance",
			Class: ClassPrivacy, SourceType: "guidance", Jurisdiction: jkg.JurisdictionSG, Authority: jkg.RegulatorID("SG-PDPC"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.pdpc.gov.sg/", AuthType: AuthNone,
			Notes: "Advisory guidelines, decisions, breach guidance.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 7 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/GuidanceRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Personal Data Protection Commission Singapore", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "jp-appi", Name: "Japan PPC (APPI)", Description: "Guidelines, enforcement, cross-border transfer guidance",
			Class: ClassPrivacy, SourceType: "guidance", Jurisdiction: jkg.JurisdictionJP, Authority: jkg.RegulatorID("JP-PPC"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.ppc.go.jp/en/", AuthType: AuthNone,
			Notes: "Guidelines, enforcement, cross-border transfer guidance.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 7 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/GuidanceRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Personal Information Protection Commission Japan", CreatedAt: now, LastUpdated: now,
		},

		// ──────────────── Class 3: AI GOVERNANCE ────────────────
		{
			SourceID: "eu-ai-act", Name: "EU AI Act (EUR-Lex)", Description: "Final text + consolidated versions by CELEX and ELI",
			Class: ClassAIGovernance, SourceType: "regulation", Jurisdiction: jkg.JurisdictionEU, Authority: jkg.RegulatorID("EU-OP"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://eur-lex.europa.eu/", AuthType: AuthNone,
			Notes: "Adapter tracks final text + consolidated versions by CELEX and ELI.", FetchPolicyConfig: eurLexFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/AIObligationRecord.v1"},
			EvidenceRules: lawEvidence, Provenance: "Official Journal of the European Union", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "us-nist-ai-rmf", Name: "NIST AI Risk Management Framework (AI RMF)", Description: "AI RMF page + linked PDFs and profiles",
			Class: ClassAIGovernance, SourceType: "standard", Jurisdiction: jkg.JurisdictionUS, Authority: jkg.RegulatorID("US-NIST"), Binding: BindingnessStandard,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.nist.gov/itl/ai-risk-management-framework", AuthType: AuthNone,
			Notes: "AI RMF page + linked PDFs and profiles; adapter follows canonical downloads.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 7 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/AIObligationRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "National Institute of Standards and Technology", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "global-oecd-ai", Name: "OECD AI Principles", Description: "Global baseline principles used as Tier-1 primitives",
			Class: ClassAIGovernance, SourceType: "standard", Jurisdiction: jkg.JurisdictionGlobal, Authority: jkg.RegulatorID("GLOBAL-OECD"), Binding: BindingnessAdvisory,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://oecd.ai/en/ai-principles", AuthType: AuthNone,
			Notes: "Global baseline principles used as Tier-1 primitives where applicable.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 30 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/AIObligationRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Organization for Economic Co-operation and Development", CreatedAt: now, LastUpdated: now,
		},

		// ──────────────── Class 4: SANCTIONS / AML ────────────────
		{
			SourceID: "un-scsl", Name: "UN Security Council Consolidated List", Description: "Global sanctions list",
			Class: ClassSanctions, SourceType: "sanctions_list", Jurisdiction: jkg.JurisdictionGlobal, Authority: jkg.RegulatorID("UN-SC"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://main.un.org/securitycouncil/en/content/un-sc-consolidated-list", AuthType: AuthNone,
			Notes: "Adapter discovers current XML/CSV distributions from the official page.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 6 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/SanctionsEntityRecord.v1"},
			EvidenceRules: sigEvidence, Provenance: "United Nations Security Council", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "us-ofac-sdn", Name: "US OFAC Sanctions List Service (SLS)", Description: "SDN + Consolidated datasets (XML/CSV/advanced XML)",
			Class: ClassSanctions, SourceType: "sanctions_list", Jurisdiction: jkg.JurisdictionUS, Authority: jkg.RegulatorID("US-OFAC"), Binding: BindingnessLaw,
			FetchMethod: FetchStructuredDownload, EndpointURL: "https://ofac.treasury.gov/sanctions-list-service", AuthType: AuthNone,
			Notes: "Adapter pulls SDN + Consolidated datasets (XML/CSV/advanced XML).", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 2 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/SanctionsEntityRecord.v1"},
			EvidenceRules: sigEvidence, Provenance: "US Department of the Treasury, OFAC", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "eu-sanctions", Name: "EU Financial Sanctions Consolidated List", Description: "EU financial sanctions dataset via data.europa.eu",
			Class: ClassSanctions, SourceType: "sanctions_list", Jurisdiction: jkg.JurisdictionEU, Authority: jkg.RegulatorID("EU-EEAS"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://data.europa.eu/data/datasets/consolidated-list-of-persons-groups-and-entities-subject-to-eu-financial-sanctions", AuthType: AuthNone,
			Notes: "Adapter resolves latest distribution(s) and hashes the retrieved artifact.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 6 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/SanctionsEntityRecord.v1"},
			EvidenceRules: sigEvidence, Provenance: "European Commission", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "uk-sanctions", Name: "UK Sanctions List", Description: "Authoritative UK sanctions list",
			Class: ClassSanctions, SourceType: "sanctions_list", Jurisdiction: jkg.JurisdictionGB, Authority: jkg.RegulatorID("UK-OFSI"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.gov.uk/government/publications/the-uk-sanctions-list", AuthType: AuthNone,
			Notes: "Adapter discovers current downloadable formats from publication attachments.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 6 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/SanctionsEntityRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "HM Treasury, OFSI", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "us-bis-entity-list", Name: "US BIS Entity List", Description: "Export control entity list",
			Class: ClassSanctions, SourceType: "sanctions_list", Jurisdiction: jkg.JurisdictionUS, Authority: jkg.RegulatorID("US-BIS"), Binding: BindingnessRegulation,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.bis.gov/entity-list", AuthType: AuthNone,
			Notes: "Adapter discovers CSV distribution (Entity List) and normalizes parties.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 12 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/SanctionsEntityRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "US Bureau of Industry and Security", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "us-csl-trade", Name: "US Consolidated Screening List (Trade.gov)", Description: "Unified screening API",
			Class: ClassSanctions, SourceType: "sanctions_list", Jurisdiction: jkg.JurisdictionUS, Authority: jkg.RegulatorID("US-ITA"), Binding: BindingnessRegulation,
			FetchMethod: FetchREST, EndpointURL: "https://api.trade.gov/gateway/v1/consolidated_screening_list", AuthType: AuthAPIKey,
			Notes: "Unified screening API; adapter emits ScreeningReceipt with match trace.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 2 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/SanctionsEntityRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "International Trade Administration", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "global-fatf", Name: "FATF High-Risk and Monitored Jurisdictions", Description: "Call for Action + Increased Monitoring",
			Class: ClassSanctions, SourceType: "advisory", Jurisdiction: jkg.JurisdictionGlobal, Authority: jkg.RegulatorID("GLOBAL-FATF"), Binding: BindingnessAdvisory,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.fatf-gafi.org/en/topics/high-risk-and-other-monitored-jurisdictions.html", AuthType: AuthNone,
			Notes: "Adapter tracks current Call for Action + Increased Monitoring outputs.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/SanctionsEntityRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Financial Action Task Force", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "global-worldbank-debarred", Name: "World Bank Debarred Firms and Individuals", Description: "Anti-corruption procurement exclusion list",
			Class: ClassSanctions, SourceType: "sanctions_list", Jurisdiction: jkg.JurisdictionGlobal, Authority: jkg.RegulatorID("WB-SANCTIONS"), Binding: BindingnessAdvisory,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.worldbank.org/en/projects-operations/procurement/debarred-firms", AuthType: AuthNone,
			Notes: "Anti-corruption procurement exclusion list (global screening input).", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/SanctionsEntityRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "World Bank Group", CreatedAt: now, LastUpdated: now,
		},

		// ──────────────── Class 5: SECURITY CONTROLS ────────────────
		{
			SourceID: "us-nist-csf", Name: "NIST Cybersecurity Framework (CSF)", Description: "CSF 2.0 and related mappings",
			Class: ClassSecurityControls, SourceType: "standard", Jurisdiction: jkg.JurisdictionUS, Authority: jkg.RegulatorID("US-NIST"), Binding: BindingnessStandard,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.nist.gov/cyberframework", AuthType: AuthNone,
			Notes: "Framework page + canonical downloads (CSF 2.0 and related mappings).", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 30 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/ControlCatalogRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "National Institute of Standards and Technology", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "us-nist-800-53", Name: "NIST SP 800-53 Rev. 5", Description: "Control catalog used to seed Tier-1 ControlLanguagePrimitive set",
			Class: ClassSecurityControls, SourceType: "standard", Jurisdiction: jkg.JurisdictionUS, Authority: jkg.RegulatorID("US-NIST"), Binding: BindingnessStandard,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final", AuthType: AuthNone,
			Notes: "Control catalog used to seed Tier-1 ControlLanguagePrimitive set.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 90 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/ControlCatalogRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "National Institute of Standards and Technology", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "global-pci-dss", Name: "PCI SSC Document Library (PCI DSS)", Description: "PCI DSS versioned documents + supporting guidance",
			Class: ClassSecurityControls, SourceType: "standard", Jurisdiction: jkg.JurisdictionGlobal, Authority: jkg.RegulatorID("PCI-SSC"), Binding: BindingnessStandard,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.pcisecuritystandards.org/document_library/", AuthType: AuthNone,
			Notes: "Adapter tracks PCI DSS versioned documents + supporting guidance.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 30 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/ControlCatalogRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "PCI Security Standards Council", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "global-cis-controls", Name: "CIS Critical Security Controls", Description: "Industry baseline controls and mappings",
			Class: ClassSecurityControls, SourceType: "standard", Jurisdiction: jkg.JurisdictionGlobal, Authority: jkg.RegulatorID("CIS"), Binding: BindingnessStandard,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.cisecurity.org/controls", AuthType: AuthNone,
			Notes: "Industry baseline controls; adapter captures version changes and mappings.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 30 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/ControlCatalogRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Center for Internet Security", CreatedAt: now, LastUpdated: now,
		},

		// ──────────────── Class 6: RESILIENCE ────────────────
		{
			SourceID: "eu-nis2", Name: "EU NIS2 Directive", Description: "Operational + cyber resilience for essential/important entities",
			Class: ClassResilience, SourceType: "directive", Jurisdiction: jkg.JurisdictionEU, Authority: jkg.RegulatorID("EU-OP"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://eur-lex.europa.eu/eli/dir/2022/2555/oj", AuthType: AuthNone,
			Notes: "Operational + cyber resilience obligations for essential/important entities.", FetchPolicyConfig: eurLexFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 7 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/ResilienceObligationRecord.v1"},
			EvidenceRules: lawEvidence, Provenance: "Official Journal of the European Union", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "eu-dora", Name: "EU DORA Regulation", Description: "Digital operational resilience (financial sector)",
			Class: ClassResilience, SourceType: "regulation", Jurisdiction: jkg.JurisdictionEU, Authority: jkg.RegulatorID("EU-OP"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://eur-lex.europa.eu/eli/reg/2022/2554/oj", AuthType: AuthNone,
			Notes: "Digital operational resilience (financial sector) controls + reporting.", FetchPolicyConfig: eurLexFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 7 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/ResilienceObligationRecord.v1"},
			EvidenceRules: lawEvidence, Provenance: "Official Journal of the European Union", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "us-hipaa", Name: "US HHS HIPAA Security Rule", Description: "Security rule guidance and implementation resources",
			Class: ClassResilience, SourceType: "regulation", Jurisdiction: jkg.JurisdictionUS, Authority: jkg.RegulatorID("US-HHS"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.hhs.gov/hipaa/for-professionals/security/index.html", AuthType: AuthNone,
			Notes: "Security rule guidance and implementation resources.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 30 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/ResilienceObligationRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "US Department of Health and Human Services", CreatedAt: now, LastUpdated: now,
		},

		// ──────────────── Class 7: IDENTITY / TRUST ────────────────
		{
			SourceID: "eu-eidas", Name: "EU eIDAS Regulation (EU 910/2014)", Description: "Trust services and electronic identification",
			Class: ClassIdentityTrust, SourceType: "regulation", Jurisdiction: jkg.JurisdictionEU, Authority: jkg.RegulatorID("EU-OP"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://eur-lex.europa.eu/eli/reg/2014/910/oj/eng", AuthType: AuthNone,
			Notes: "Trust services and electronic identification legal basis.", FetchPolicyConfig: eurLexFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 30 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/TrustAnchorRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Official Journal of the European Union", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "eu-lotl", Name: "EU List of Trusted Lists (LOTL)", Description: "Machine-readable XML of qualified trust service providers",
			Class: ClassIdentityTrust, SourceType: "trust_list", Jurisdiction: jkg.JurisdictionEU, Authority: jkg.RegulatorID("EU-EC"), Binding: BindingnessRegulation,
			FetchMethod: FetchStructuredDownload, EndpointURL: "https://ec.europa.eu/tools/lotl/eu-lotl.xml", AuthType: AuthNone,
			Notes: "Adapter verifies XML signature and extracts TSL pointers.", FetchPolicyConfig: defaultFP,
			Trust: trustSignedXML, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/TrustAnchorRecord.v1"},
			EvidenceRules: sigEvidence, Provenance: "European Commission", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "global-cab-forum", Name: "CA/Browser Forum Baseline Requirements", Description: "BRs for publicly-trusted TLS certificates",
			Class: ClassIdentityTrust, SourceType: "standard", Jurisdiction: jkg.JurisdictionGlobal, Authority: jkg.RegulatorID("CA-BFORUM"), Binding: BindingnessStandard,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://cabforum.org/baseline-requirements-documents/", AuthType: AuthNone,
			Notes: "Baseline Requirements for publicly-trusted TLS certificates.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 30 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/TrustAnchorRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "CA/Browser Forum", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "global-ct-chrome", Name: "Chrome CT Log List (v3, signed JSON)", Description: "Signed CT log list used by Chrome policy enforcement",
			Class: ClassIdentityTrust, SourceType: "trust_list", Jurisdiction: jkg.JurisdictionGlobal, Authority: jkg.RegulatorID("GOOGLE-CT"), Binding: BindingnessStandard,
			FetchMethod: FetchStructuredDownload, EndpointURL: "https://www.gstatic.com/ct/log_list/v3/log_list.json", AuthType: AuthNone,
			Notes: "Signed CT log list used by Chrome policy enforcement.", FetchPolicyConfig: defaultFP,
			Trust: trustSignedJSON, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/TrustAnchorRecord.v1"},
			EvidenceRules: sigEvidence, Provenance: "Google Certificate Transparency", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "global-ct-apple", Name: "Apple CT Log List", Description: "Apple CT log policy and download links",
			Class: ClassIdentityTrust, SourceType: "trust_list", Jurisdiction: jkg.JurisdictionGlobal, Authority: jkg.RegulatorID("APPLE-CT"), Binding: BindingnessStandard,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://support.apple.com/en-us/103214", AuthType: AuthNone,
			Notes: "Adapter discovers current JSON download URLs and verifies integrity via hash chain.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/TrustAnchorRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Apple Inc.", CreatedAt: now, LastUpdated: now,
		},

		// ──────────────── Class 8: SUPPLY CHAIN ────────────────
		{
			SourceID: "us-cisa-kev", Name: "CISA Known Exploited Vulnerabilities (KEV)", Description: "Exploit-in-the-wild signal for patch policy",
			Class: ClassSupplyChain, SourceType: "vuln_feed", Jurisdiction: jkg.JurisdictionUS, Authority: jkg.RegulatorID("US-CISA"), Binding: BindingnessAdvisory,
			FetchMethod: FetchStructuredDownload, EndpointURL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", AuthType: AuthNone,
			Notes: "Exploit-in-the-wild signal; used for fail-closed patch and allowlist policy.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 6 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/VulnRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Cybersecurity and Infrastructure Security Agency", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "global-nvd", Name: "NVD CVE API (2.0)", Description: "Primary CVE enrichment source (CVSS, CPEs, references)",
			Class: ClassSupplyChain, SourceType: "vuln_feed", Jurisdiction: jkg.JurisdictionUS, Authority: jkg.RegulatorID("US-NIST"), Binding: BindingnessAdvisory,
			FetchMethod: FetchREST, EndpointURL: "https://services.nvd.nist.gov/rest/json/cves/2.0", AuthType: AuthAPIKey,
			Notes: "Primary CVE enrichment source (CVSS, CPEs, references).", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "realtime", TTL: 6 * time.Hour, ChangeDetection: "etag",
			ChangeDetectorConfig: etagCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/VulnRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "National Institute of Standards and Technology", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "global-osv", Name: "OSV (Open Source Vulnerabilities) API", Description: "Package-first vulnerability intelligence",
			Class: ClassSupplyChain, SourceType: "vuln_feed", Jurisdiction: jkg.JurisdictionGlobal, Authority: jkg.RegulatorID("OSV"), Binding: BindingnessAdvisory,
			FetchMethod: FetchREST, EndpointURL: "https://api.osv.dev/", AuthType: AuthNone,
			Notes: "Package-first vulnerability intelligence (Go, npm, PyPI, Maven, etc.).", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "realtime", TTL: 6 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/VulnRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Google Open Source Security Team", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "global-rekor", Name: "Sigstore Rekor Transparency Log", Description: "Transparency log for software artifact provenance",
			Class: ClassSupplyChain, SourceType: "transparency_log", Jurisdiction: jkg.JurisdictionGlobal, Authority: jkg.RegulatorID("SIGSTORE"), Binding: BindingnessStandard,
			FetchMethod: FetchREST, EndpointURL: "https://rekor.sigstore.dev/api/v1/", AuthType: AuthNone,
			Notes: "Transparency log for software artifacts; adapter emits inclusion-proof evidence.", FetchPolicyConfig: defaultFP,
			Trust: trustTransparencyLog, UpdateCadence: "realtime", TTL: 2 * time.Hour, ChangeDetection: "sequence",
			ChangeDetectorConfig: seqCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/VulnRecord.v1"},
			EvidenceRules: sigEvidence, Provenance: "Linux Foundation / Sigstore", CreatedAt: now, LastUpdated: now,
		},

		// ──────────────── Class 9: CERTIFICATION ────────────────
		{
			SourceID: "us-fedramp", Name: "FedRAMP Marketplace", Description: "Authorized services and package pointers for evidence linking",
			Class: ClassCertification, SourceType: "cert_program", Jurisdiction: jkg.JurisdictionUS, Authority: jkg.RegulatorID("US-FEDRAMP"), Binding: BindingnessRegulation,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://marketplace.fedramp.gov/", AuthType: AuthNone,
			Notes: "Adapter extracts authorized services and package pointers for evidence linking.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 7 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/CertificationProgramRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "FedRAMP PMO", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "global-csa-star", Name: "CSA STAR Registry (API)", Description: "Cloud services and assurance artifacts (CAIQ, etc.)",
			Class: ClassCertification, SourceType: "cert_program", Jurisdiction: jkg.JurisdictionGlobal, Authority: jkg.RegulatorID("CSA"), Binding: BindingnessStandard,
			FetchMethod: FetchREST, EndpointURL: "https://star.watch/api/v1/registry/cloud_services", AuthType: AuthNone,
			Notes: "Registry of cloud services and assurance artifacts (CAIQ, etc.).", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "weekly", TTL: 7 * 24 * time.Hour, ChangeDetection: "hash",
			ChangeDetectorConfig: hashCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/CertificationProgramRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Cloud Security Alliance", CreatedAt: now, LastUpdated: now,
		},

		// ──────────────── Class 10: ENTITY REGISTRY ────────────────
		{
			SourceID: "global-gleif", Name: "GLEIF LEI Records API", Description: "Legal entity identity (LEI) for counterparty compliance",
			Class: ClassEntityRegistry, SourceType: "entity_registry", Jurisdiction: jkg.JurisdictionGlobal, Authority: jkg.RegulatorID("GLOBAL-GLEIF"), Binding: BindingnessStandard,
			FetchMethod: FetchREST, EndpointURL: "https://api.gleif.org/api/v1/lei-records", AuthType: AuthNone,
			Notes: "Legal entity identity (LEI) for counterparty compliance and screening joins.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "etag",
			ChangeDetectorConfig: etagCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/EntityIdentityRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "Global Legal Entity Identifier Foundation", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "uk-companies-house", Name: "UK Companies House API", Description: "Company identity, filings, officers; beneficial ownership",
			Class: ClassEntityRegistry, SourceType: "entity_registry", Jurisdiction: jkg.JurisdictionGB, Authority: jkg.RegulatorID("UK-CH"), Binding: BindingnessRegulation,
			FetchMethod: FetchREST, EndpointURL: "https://api.company-information.service.gov.uk/", AuthType: AuthAPIKey,
			Notes: "Company identity, filings, officers; used for beneficial ownership joins.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "etag",
			ChangeDetectorConfig: etagCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/EntityIdentityRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "UK Companies House", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "us-sec-edgar", Name: "SEC EDGAR Submissions (JSON)", Description: "Company submissions JSON",
			Class: ClassEntityRegistry, SourceType: "entity_registry", Jurisdiction: jkg.JurisdictionUS, Authority: jkg.RegulatorID("US-SEC"), Binding: BindingnessRegulation,
			FetchMethod: FetchREST, EndpointURL: "https://data.sec.gov/submissions/", AuthType: AuthNone,
			Notes: "Company submissions JSON; adapter enforces SEC header policy and caching.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "etag",
			ChangeDetectorConfig: etagCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/EntityIdentityRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "US Securities and Exchange Commission", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "us-sec-edgar-xbrl", Name: "SEC EDGAR XBRL (JSON)", Description: "XBRL frames/company facts for compliance-grade entity financial signals",
			Class: ClassEntityRegistry, SourceType: "entity_registry", Jurisdiction: jkg.JurisdictionUS, Authority: jkg.RegulatorID("US-SEC"), Binding: BindingnessRegulation,
			FetchMethod: FetchREST, EndpointURL: "https://data.sec.gov/api/xbrl/", AuthType: AuthNone,
			Notes: "XBRL frames/company facts for compliance-grade entity financial signals.", FetchPolicyConfig: defaultFP,
			Trust: trustTLSHashChain, UpdateCadence: "daily", TTL: 24 * time.Hour, ChangeDetection: "etag",
			ChangeDetectorConfig: etagCD, Normalization: NormalizationMapping{ObligationSchema: "helm://schemas/compliance/EntityIdentityRecord.v1"},
			EvidenceRules: stdEvidence, Provenance: "US Securities and Exchange Commission", CreatedAt: now, LastUpdated: now,
		},
	}

	return append(base, DefaultComplianceSourcesBatch2()...)
}

// SeedRegistry seeds a registry with all default compliance sources.
// This is the entry point for `helm bootstrap`.
func SeedRegistry(reg ComplianceSourceRegistry) error {
	for _, src := range DefaultComplianceSources() {
		if err := reg.Register(src); err != nil {
			return err
		}
	}
	return nil
}
