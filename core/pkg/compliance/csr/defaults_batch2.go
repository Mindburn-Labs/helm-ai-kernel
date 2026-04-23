package csr

import (
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// DefaultComplianceSourcesBatch2 returns Batch 2 sources:
//   - North America: Canada, Mexico
//   - EU-27 member states (LAW via N-Lex gateway + per-country PRIVACY DPA)
//   - EEA non-EU: Norway, Iceland, Liechtenstein
//   - Switzerland
//   - Other highly regulated regions: Australia, New Zealand, South Korea, Hong Kong, India
//
// All sources use the Batch 1 trust presets for EvidencePack consistency.
func DefaultComplianceSourcesBatch2() []*ComplianceSource {
	now := time.Now()

	// Trust presets — identical to Batch 1 to keep EvidencePack diffs clean.
	trustGovWeb := TrustModel{
		RequireTLS: true, TLSMinVersion: "1.2",
		HashChain: "sha256+rfc8785-json", TimestampPolicy: "http-date",
	}
	trustGovWebSignedPDF := TrustModel{
		RequireTLS: true, TLSMinVersion: "1.2",
		RequireSignature: true, SignatureFormat: "pkcs7-pdf",
		HashChain: "sha256+rfc8785-json", TimestampPolicy: "http-date",
	}

	defaultFP := DefaultFetchPolicy()
	stdEvidence := EvidenceEmissionRules{EmitSourceVersion: true, EmitContentHash: true, EmitRetrievalTime: true}
	lawEvidence := EvidenceEmissionRules{EmitSourceVersion: true, EmitContentHash: true, EmitRetrievalTime: true, EmitAmendmentsChain: true}
	hashCD := ChangeDetector{Strategy: "hash", HashAlgorithm: "sha256", DiffMode: "full"}

	lawNorm := NormalizationMapping{ObligationSchema: "helm://schemas/compliance/LegalSourceRecord.v1"}
	privNorm := NormalizationMapping{ObligationSchema: "helm://schemas/compliance/GuidanceRecord.v1"}

	// Helper for the very repetitive N-Lex LAW entries.
	nlexLaw := func(id string, cc string, endpoint string) *ComplianceSource {
		return &ComplianceSource{
			SourceID: id, Name: "N-Lex (" + cc + ")", Description: "National legislation via N-Lex gateway",
			Class: ClassLaw, SourceType: "nlex_gateway", Jurisdiction: jkg.JurisdictionCode(cc),
			Binding: BindingnessLaw, FetchMethod: FetchHTMLScrape, EndpointURL: endpoint, AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 72 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: stdEvidence, Provenance: "N-Lex / European Commission", CreatedAt: now, LastUpdated: now,
		}
	}

	// Helper for the very repetitive per-country PRIVACY DPA entries.
	privDPA := func(id string, cc string, authority string, name string, endpoint string) *ComplianceSource {
		return &ComplianceSource{
			SourceID: id, Name: name, Description: "Data Protection Authority publications",
			Class: ClassPrivacy, SourceType: "privacy_authority", Jurisdiction: jkg.JurisdictionCode(cc),
			Authority: jkg.RegulatorID(authority), Binding: BindingnessGuidance,
			FetchMethod: FetchHTMLScrape, EndpointURL: endpoint, AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 72 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: privNorm,
			EvidenceRules: stdEvidence, Provenance: name, CreatedAt: now, LastUpdated: now,
		}
	}

	return []*ComplianceSource{
		// ────────────────────────────────────────────────────────────
		// NORTH AMERICA
		// ────────────────────────────────────────────────────────────

		// Canada (CA)
		{
			SourceID: "ca-justice-laws", Name: "Canada Justice Laws Website", Description: "Consolidated Acts and Regulations",
			Class: ClassLaw, SourceType: "law_portal", Jurisdiction: jkg.JurisdictionCode("CA"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://laws-lois.justice.gc.ca/eng/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 48 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: lawEvidence, Provenance: "Department of Justice Canada", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "ca-gazette", Name: "Canada Gazette", Description: "Official gazette of the Government of Canada",
			Class: ClassLaw, SourceType: "official_gazette", Jurisdiction: jkg.JurisdictionCode("CA"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://gazette.gc.ca/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 48 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: lawEvidence, Provenance: "Government of Canada", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "ca-opc", Name: "Canada OPC (Privacy Commissioner)", Description: "PIPEDA/Privacy Act guidance and decisions",
			Class: ClassPrivacy, SourceType: "privacy_authority", Jurisdiction: jkg.JurisdictionCode("CA"),
			Authority: jkg.RegulatorID("CA-OPC"), Binding: BindingnessGuidance,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.priv.gc.ca/en/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 72 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: privNorm,
			EvidenceRules: stdEvidence, Provenance: "Office of the Privacy Commissioner of Canada", CreatedAt: now, LastUpdated: now,
		},

		// Mexico (MX)
		{
			SourceID: "mx-dof", Name: "Mexico Diario Oficial de la Federación", Description: "Official gazette of Mexico",
			Class: ClassLaw, SourceType: "official_gazette", Jurisdiction: jkg.JurisdictionCode("MX"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.dof.gob.mx/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "12h", TTL: 24 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: lawEvidence, Provenance: "Gobierno de México", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "mx-tpp", Name: "Mexico Transparencia para el Pueblo", Description: "Privacy and transparency authority (post-INAI)",
			Class: ClassPrivacy, SourceType: "privacy_authority", Jurisdiction: jkg.JurisdictionCode("MX"),
			Authority: jkg.RegulatorID("MX-TPP"), Binding: BindingnessGuidance,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.transparencia.gob.mx/", AuthType: AuthNone,
			Notes:             "Transparencia para el Pueblo replaced INAI (dissolved 2025).",
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 72 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: privNorm,
			EvidenceRules: stdEvidence, Provenance: "Transparencia para el Pueblo", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "mx-pnt", Name: "Mexico Plataforma Nacional de Transparencia", Description: "National transparency portal",
			Class: ClassLaw, SourceType: "registry_portal", Jurisdiction: jkg.JurisdictionCode("MX"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.plataformadetransparencia.org.mx/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 72 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: stdEvidence, Provenance: "Plataforma Nacional de Transparencia", CreatedAt: now, LastUpdated: now,
		},

		// ────────────────────────────────────────────────────────────
		// EU-27 MEMBER STATES: LAW (N-Lex) + PRIVACY (DPA)
		// ────────────────────────────────────────────────────────────

		// Austria (AT)
		nlexLaw("at-nlex", "AT", "https://n-lex.europa.eu/n-lex/info/info-at/index"),
		privDPA("at-dsb", "AT", "AT-DSB", "Austria DSB", "https://www.dsb.gv.at/"),

		// Belgium (BE)
		nlexLaw("be-nlex", "BE", "https://n-lex.europa.eu/n-lex/info/info-be/index"),
		privDPA("be-apd", "BE", "BE-APD", "Belgium APD/GBA", "https://www.autoriteprotectiondonnees.be/"),

		// Bulgaria (BG)
		nlexLaw("bg-nlex", "BG", "https://n-lex.europa.eu/n-lex/info/info-bg/index"),
		privDPA("bg-cpdp", "BG", "BG-CPDP", "Bulgaria CPDP", "https://www.cpdp.bg/"),

		// Croatia (HR)
		nlexLaw("hr-nlex", "HR", "https://n-lex.europa.eu/n-lex/info/info-hr/index"),
		privDPA("hr-azop", "HR", "HR-AZOP", "Croatia AZOP", "https://azop.hr/"),

		// Cyprus (CY)
		nlexLaw("cy-nlex", "CY", "https://n-lex.europa.eu/n-lex/info/info-cy/index"),
		privDPA("cy-dpc", "CY", "CY-DPC", "Cyprus Data Protection Commissioner", "https://www.dataprotection.gov.cy/"),

		// Czech Republic (CZ)
		nlexLaw("cz-nlex", "CZ", "https://n-lex.europa.eu/n-lex/info/info-cz/index"),
		privDPA("cz-uoou", "CZ", "CZ-UOOU", "Czech ÚOOÚ", "https://uoou.gov.cz/en"),

		// Denmark (DK)
		nlexLaw("dk-nlex", "DK", "https://n-lex.europa.eu/n-lex/info/info-dk/index"),
		privDPA("dk-datatilsynet", "DK", "DK-DATATILSYNET", "Denmark Datatilsynet", "https://www.datatilsynet.dk/"),

		// Estonia (EE)
		nlexLaw("ee-nlex", "EE", "https://n-lex.europa.eu/n-lex/info/info-ee/index"),
		privDPA("ee-aki", "EE", "EE-AKI", "Estonia AKI", "https://www.aki.ee/"),

		// Finland (FI)
		nlexLaw("fi-nlex", "FI", "https://n-lex.europa.eu/n-lex/info/info-fi/index"),
		privDPA("fi-tietosuoja", "FI", "FI-TSV", "Finland Tietosuojavaltuutettu", "https://tietosuoja.fi/"),

		// France (FR) — CNIL DPA already in Batch 1; add LAW only
		nlexLaw("fr-nlex", "FR", "https://n-lex.europa.eu/n-lex/info/info-fr/index"),

		// Germany (DE)
		nlexLaw("de-nlex", "DE", "https://n-lex.europa.eu/n-lex/info/info-de/index"),
		privDPA("de-bfdi", "DE", "DE-BFDI", "Germany BfDI", "https://www.bfdi.bund.de/"),

		// Greece (GR)
		nlexLaw("gr-nlex", "GR", "https://n-lex.europa.eu/n-lex/info/info-el/index"),
		privDPA("gr-hdpa", "GR", "GR-HDPA", "Greece HDPA", "https://www.dpa.gr/"),

		// Hungary (HU) — signed-PDF gazette
		{
			SourceID: "hu-magyarkozlony", Name: "Hungary Magyar Közlöny", Description: "Official Gazette (signed-PDF)",
			Class: ClassLaw, SourceType: "official_gazette", Jurisdiction: jkg.JurisdictionCode("HU"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://magyarkozlony.hu/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWebSignedPDF, UpdateCadence: "daily", TTL: 72 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: lawEvidence, Provenance: "Magyar Közlöny", CreatedAt: now, LastUpdated: now,
		},
		privDPA("hu-naih", "HU", "HU-NAIH", "Hungary NAIH", "https://www.naih.hu/"),

		// Ireland (IE)
		nlexLaw("ie-nlex", "IE", "https://n-lex.europa.eu/n-lex/info/info-ie/index"),
		privDPA("ie-dpc", "IE", "IE-DPC", "Ireland DPC", "https://www.dataprotection.ie/"),

		// Italy (IT)
		nlexLaw("it-nlex", "IT", "https://n-lex.europa.eu/n-lex/info/info-it/index"),
		privDPA("it-garante", "IT", "IT-GARANTE", "Italy Garante", "https://www.garanteprivacy.it/"),

		// Latvia (LV)
		nlexLaw("lv-nlex", "LV", "https://n-lex.europa.eu/n-lex/info/info-lv/index"),
		privDPA("lv-dvi", "LV", "LV-DVI", "Latvia DVI", "https://www.dvi.gov.lv/"),

		// Lithuania (LT)
		nlexLaw("lt-nlex", "LT", "https://n-lex.europa.eu/n-lex/info/info-lt/index"),
		privDPA("lt-vdai", "LT", "LT-VDAI", "Lithuania VDAI", "https://vdai.lrv.lt/"),

		// Luxembourg (LU)
		nlexLaw("lu-nlex", "LU", "https://n-lex.europa.eu/n-lex/info/info-lu/index"),
		privDPA("lu-cnpd", "LU", "LU-CNPD", "Luxembourg CNPD", "https://cnpd.public.lu/"),

		// Malta (MT)
		nlexLaw("mt-nlex", "MT", "https://n-lex.europa.eu/n-lex/info/info-mt/index"),
		privDPA("mt-idpc", "MT", "MT-IDPC", "Malta IDPC", "https://idpc.org.mt/"),

		// Netherlands (NL)
		nlexLaw("nl-nlex", "NL", "https://n-lex.europa.eu/n-lex/info/info-nl/index"),
		privDPA("nl-ap", "NL", "NL-AP", "Netherlands Autoriteit Persoonsgegevens", "https://autoriteitpersoonsgegevens.nl/"),

		// Poland (PL)
		nlexLaw("pl-nlex", "PL", "https://n-lex.europa.eu/n-lex/info/info-pl/index"),
		privDPA("pl-uodo", "PL", "PL-UODO", "Poland UODO", "https://uodo.gov.pl/"),

		// Portugal (PT)
		nlexLaw("pt-nlex", "PT", "https://n-lex.europa.eu/n-lex/info/info-pt/index"),
		privDPA("pt-cnpd", "PT", "PT-CNPD", "Portugal CNPD", "https://www.cnpd.pt/"),

		// Romania (RO)
		nlexLaw("ro-nlex", "RO", "https://n-lex.europa.eu/n-lex/info/info-ro/index"),
		privDPA("ro-anspdcp", "RO", "RO-ANSPDCP", "Romania ANSPDCP", "https://www.dataprotection.ro/"),

		// Slovakia (SK)
		nlexLaw("sk-nlex", "SK", "https://n-lex.europa.eu/n-lex/info/info-sk/index"),
		privDPA("sk-uoou", "SK", "SK-UOOU", "Slovakia ÚOOU", "https://dataprotection.gov.sk/en/"),

		// Slovenia (SI)
		nlexLaw("si-nlex", "SI", "https://n-lex.europa.eu/n-lex/info/info-si/index"),
		privDPA("si-iprs", "SI", "SI-IPRS", "Slovenia IP-RS", "https://www.ip-rs.si/"),

		// Spain (ES)
		nlexLaw("es-nlex", "ES", "https://n-lex.europa.eu/n-lex/info/info-es/index"),
		privDPA("es-aepd", "ES", "ES-AEPD", "Spain AEPD", "https://www.aepd.es/"),

		// Sweden (SE)
		nlexLaw("se-nlex", "SE", "https://n-lex.europa.eu/n-lex/info/info-sv/index"),
		privDPA("se-imy", "SE", "SE-IMY", "Sweden IMY", "https://www.imy.se/"),

		// ────────────────────────────────────────────────────────────
		// EEA (non-EU) + Switzerland
		// ────────────────────────────────────────────────────────────

		// Norway (NO)
		{
			SourceID: "no-regjeringen", Name: "Norway Regjeringen Laws", Description: "Norwegian laws and regulations portal",
			Class: ClassLaw, SourceType: "law_portal", Jurisdiction: jkg.JurisdictionCode("NO"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.regjeringen.no/en/topics/laws-and-regulations/id2004402/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 96 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: lawEvidence, Provenance: "Regjeringen.no", CreatedAt: now, LastUpdated: now,
		},
		privDPA("no-datatilsynet", "NO", "NO-DATATILSYNET", "Norway Datatilsynet", "https://www.datatilsynet.no/en/"),

		// Iceland (IS)
		{
			SourceID: "is-althingi", Name: "Iceland Althingi Laws", Description: "Icelandic parliament legislation portal",
			Class: ClassLaw, SourceType: "law_portal", Jurisdiction: jkg.JurisdictionCode("IS"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.althingi.is/english/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 96 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: lawEvidence, Provenance: "Althingi", CreatedAt: now, LastUpdated: now,
		},
		privDPA("is-personuvernd", "IS", "IS-PERSONUVERND", "Iceland Persónuvernd", "https://www.personuvernd.is/"),

		// Liechtenstein (LI)
		{
			SourceID: "li-gesetze", Name: "Liechtenstein Gesetze.li", Description: "Liechtenstein law portal",
			Class: ClassLaw, SourceType: "law_portal", Jurisdiction: jkg.JurisdictionCode("LI"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.gesetze.li/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 96 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: lawEvidence, Provenance: "Gesetze.li", CreatedAt: now, LastUpdated: now,
		},
		privDPA("li-dss", "LI", "LI-DSS", "Liechtenstein Datenschutzstelle", "https://www.datenschutzstelle.li/"),

		// Switzerland (CH)
		{
			SourceID: "ch-fedlex", Name: "Switzerland Fedlex", Description: "Swiss federal legislation portal",
			Class: ClassLaw, SourceType: "law_portal", Jurisdiction: jkg.JurisdictionCode("CH"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.fedlex.admin.ch/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 96 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: lawEvidence, Provenance: "Bundeskanzlei (Swiss Federal Chancellery)", CreatedAt: now, LastUpdated: now,
		},
		privDPA("ch-fdpic", "CH", "CH-FDPIC", "Switzerland FDPIC", "https://www.edoeb.admin.ch/"),

		// ────────────────────────────────────────────────────────────
		// OTHER HIGHLY REGULATED REGIONS
		// ────────────────────────────────────────────────────────────

		// Australia (AU)
		{
			SourceID: "au-legislation", Name: "Australia Federal Register of Legislation", Description: "Commonwealth Acts and legislative instruments",
			Class: ClassLaw, SourceType: "law_portal", Jurisdiction: jkg.JurisdictionCode("AU"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.legislation.gov.au/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 72 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: lawEvidence, Provenance: "Federal Register of Legislation, Australia", CreatedAt: now, LastUpdated: now,
		},
		privDPA("au-oaic", "AU", "AU-OAIC", "Australia OAIC", "https://www.oaic.gov.au/"),

		// New Zealand (NZ)
		{
			SourceID: "nz-legislation", Name: "New Zealand Legislation", Description: "Acts and statutory instruments",
			Class: ClassLaw, SourceType: "law_portal", Jurisdiction: jkg.JurisdictionCode("NZ"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.legislation.govt.nz/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 96 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: lawEvidence, Provenance: "Parliamentary Counsel Office, New Zealand", CreatedAt: now, LastUpdated: now,
		},
		privDPA("nz-opc", "NZ", "NZ-OPC", "New Zealand OPC", "https://www.privacy.org.nz/"),

		// South Korea (KR)
		{
			SourceID: "kr-law", Name: "South Korea Law.go.kr", Description: "Korean legislation information system",
			Class: ClassLaw, SourceType: "law_portal", Jurisdiction: jkg.JurisdictionCode("KR"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.law.go.kr/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 96 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: lawEvidence, Provenance: "Korean Law Information Center", CreatedAt: now, LastUpdated: now,
		},
		privDPA("kr-pipc", "KR", "KR-PIPC", "South Korea PIPC", "https://www.pipc.go.kr/"),

		// Hong Kong (HK)
		{
			SourceID: "hk-elegislation", Name: "Hong Kong e-Legislation", Description: "Hong Kong laws database",
			Class: ClassLaw, SourceType: "law_portal", Jurisdiction: jkg.JurisdictionCode("HK"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.elegislation.gov.hk/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 96 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: lawEvidence, Provenance: "Department of Justice, Hong Kong", CreatedAt: now, LastUpdated: now,
		},
		privDPA("hk-pcpd", "HK", "HK-PCPD", "Hong Kong PCPD", "https://www.pcpd.org.hk/"),

		// India (IN)
		{
			SourceID: "in-egazette", Name: "India e-Gazette", Description: "Official gazette of India",
			Class: ClassLaw, SourceType: "official_gazette", Jurisdiction: jkg.JurisdictionCode("IN"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://egazette.gov.in/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "12h", TTL: 48 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: lawEvidence, Provenance: "Government of India", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "in-indiacode", Name: "India Code", Description: "Central Acts and subordinate legislation",
			Class: ClassLaw, SourceType: "law_portal", Jurisdiction: jkg.JurisdictionCode("IN"), Binding: BindingnessLaw,
			FetchMethod: FetchHTMLScrape, EndpointURL: "https://www.indiacode.nic.in/", AuthType: AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 96 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: lawNorm,
			EvidenceRules: lawEvidence, Provenance: "Legislative Department, Ministry of Law & Justice", CreatedAt: now, LastUpdated: now,
		},
		{
			SourceID: "in-meity-dpdp", Name: "India DPDP Rules (MeitY)", Description: "Digital Personal Data Protection Rules 2025",
			Class: ClassPrivacy, SourceType: "privacy_authority", Jurisdiction: jkg.JurisdictionCode("IN"),
			Authority: jkg.RegulatorID("IN-MEITY-DPDP"), Binding: BindingnessLaw,
			FetchMethod:       FetchHTMLScrape,
			EndpointURL:       "https://www.meity.gov.in/documents/act-and-policies/digital-personal-data-protection-rules-2025",
			AuthType:          AuthNone,
			FetchPolicyConfig: defaultFP, Trust: trustGovWeb, UpdateCadence: "daily", TTL: 168 * time.Hour,
			ChangeDetection: "hash", ChangeDetectorConfig: hashCD, Normalization: privNorm,
			EvidenceRules: stdEvidence, Provenance: "Ministry of Electronics and Information Technology, India", CreatedAt: now, LastUpdated: now,
		},
	}
}
