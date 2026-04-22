package docs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewMiCAAttestation(t *testing.T) {
	ma := NewMiCAAttestation("entity-001", "CASP")
	require.NotNil(t, ma)
	require.Equal(t, "entity-001", ma.EntityID)
	require.Equal(t, "CASP", ma.EntityType)
	require.Equal(t, StatusPending, ma.Status)
}

func TestMiCAAddArticle68(t *testing.T) {
	ma := NewMiCAAttestation("entity-001", "CASP")
	ma.AddArticle68()

	require.Contains(t, ma.Articles, "68")
	article := ma.Articles["68"]
	require.Equal(t, "Orderly wind-down", article.Title)
	require.Len(t, article.Requirements, 4)
}

func TestMiCASetRequirementStatus(t *testing.T) {
	ma := NewMiCAAttestation("entity-001", "CASP")
	ma.AddArticle68()

	err := ma.SetRequirementStatus("68", "68.1.a", StatusCompliant, "Procedures documented")
	require.NoError(t, err)

	for _, req := range ma.Articles["68"].Requirements {
		if req.ID == "68.1.a" {
			require.Equal(t, StatusCompliant, req.Status)
			require.Equal(t, "Procedures documented", req.Notes)
		}
	}
}

func TestMiCASetRequirementStatusNotFound(t *testing.T) {
	ma := NewMiCAAttestation("entity-001", "CASP")
	ma.AddArticle68()

	err := ma.SetRequirementStatus("99", "99.1", StatusCompliant, "")
	require.Error(t, err)

	err = ma.SetRequirementStatus("68", "68.99", StatusCompliant, "")
	require.Error(t, err)
}

func TestMiCAAddEvidence(t *testing.T) {
	ma := NewMiCAAttestation("entity-001", "CASP")
	ma.AddArticle68()

	evidence := EvidenceRef{
		Type:        "document",
		Reference:   "DOC-001",
		Description: "Wind-down procedure documentation",
	}

	err := ma.AddEvidence("68", evidence)
	require.NoError(t, err)
	require.Len(t, ma.Articles["68"].Evidence, 1)
}

func TestMiCACalculateOverallStatus(t *testing.T) {
	ma := NewMiCAAttestation("entity-001", "CASP")
	ma.AddArticle68()
	ma.Articles["68"].Status = StatusCompliant

	ma.CalculateOverallStatus()
	require.Equal(t, StatusCompliant, ma.Status)
}

func TestMiCACalculateOverallStatusNonCompliant(t *testing.T) {
	ma := NewMiCAAttestation("entity-001", "CASP")
	ma.AddArticle68()
	ma.Articles["68"].Status = StatusNonCompliant

	ma.CalculateOverallStatus()
	require.Equal(t, StatusNonCompliant, ma.Status)
}

func TestNewAIActTransparency(t *testing.T) {
	ai := NewAIActTransparency("ai-001", "HELM Governance Engine", RiskLimited)
	require.NotNil(t, ai)
	require.Equal(t, "ai-001", ai.SystemID)
	require.Equal(t, RiskLimited, ai.RiskCategory)
	require.Equal(t, StatusPending, ai.Status)
}

func TestAIActSetTransparencyDoc(t *testing.T) {
	ai := NewAIActTransparency("ai-001", "HELM Governance Engine", RiskLimited)

	doc := TransparencyDocument{
		Purpose:      "Organizational governance",
		Capabilities: []string{"Policy evaluation", "Effect governance"},
		Limitations:  []string{"Requires human approval for high-risk actions"},
		IntendedUse:  "Enterprise governance automation",
	}

	ai.SetTransparencyDoc(doc)
	require.Equal(t, "Organizational governance", ai.TransparencyDoc.Purpose)
}

func TestAIActSetTechnicalDoc(t *testing.T) {
	ai := NewAIActTransparency("ai-001", "HELM Governance Engine", RiskHigh)

	doc := TechnicalDocument{
		Architecture:     "Event-driven state machine",
		ValidationMethod: "Automated conformance verification",
		PerformanceMetrics: map[string]float64{
			"accuracy":       0.99,
			"latency_p99_ms": 50,
		},
	}

	ai.SetTechnicalDoc(doc)
	require.Equal(t, 0.99, ai.TechnicalDoc.PerformanceMetrics["accuracy"])
}

func TestNewSOC2Attestation(t *testing.T) {
	start := time.Now().AddDate(0, -6, 0)
	end := time.Now()

	soc := NewSOC2Attestation("org-001", "HELM Corp", start, end)
	require.NotNil(t, soc)
	require.Len(t, soc.TrustPrinciples, 5)
	require.Contains(t, soc.TrustPrinciples, "security")
	require.Contains(t, soc.TrustPrinciples, "availability")
}

func TestSOC2AddControl(t *testing.T) {
	soc := NewSOC2Attestation("org-001", "HELM Corp", time.Now(), time.Now())

	err := soc.AddControl("security", "CC6.1", "Restrict logical access", "Access Control")
	require.NoError(t, err)
	require.Len(t, soc.TrustPrinciples["security"].Controls, 1)
}

func TestSOC2AddControlUnknownPrinciple(t *testing.T) {
	soc := NewSOC2Attestation("org-001", "HELM Corp", time.Now(), time.Now())

	err := soc.AddControl("unknown", "X1", "desc", "cat")
	require.Error(t, err)
}

func TestSOC2RecordTest(t *testing.T) {
	soc := NewSOC2Attestation("org-001", "HELM Corp", time.Now(), time.Now())
	_ = soc.AddControl("security", "CC6.1", "Restrict logical access", "Access Control")

	soc.RecordTest("CC6.1", "auditor1", "PASS", nil)
	require.Len(t, soc.ControlTests, 1)
	require.Equal(t, "PASS", soc.ControlTests[0].Result)
}

func TestNewAuditTrailExporter(t *testing.T) {
	exporter := NewAuditTrailExporter("org-001")
	require.NotNil(t, exporter)
	require.Contains(t, exporter.ExportFormats, "JSON")
	require.Contains(t, exporter.ExportFormats, "CEF")
}

func TestExportJSON(t *testing.T) {
	exporter := NewAuditTrailExporter("org-001")

	entries := []AuditEntry{
		{
			Timestamp: time.Now(),
			EventType: "MUTATION",
			Actor:     "user123",
			Resource:  "entity001",
			Action:    "UPDATE_POLICY",
			Outcome:   "SUCCESS",
		},
	}

	data, err := exporter.ExportJSON(entries)
	require.NoError(t, err)
	require.Contains(t, string(data), "MUTATION")
}

func TestExportCEF(t *testing.T) {
	exporter := NewAuditTrailExporter("org-001")

	entries := []AuditEntry{
		{
			EventType: "LOGIN",
			Actor:     "user123",
			Resource:  "system",
			Action:    "AUTHENTICATE",
			Outcome:   "SUCCESS",
		},
	}

	cef := exporter.ExportCEF(entries)
	require.Contains(t, cef, "CEF:0|HELM|Governance Engine|")
	require.Contains(t, cef, "LOGIN")
}

func TestExportCSV(t *testing.T) {
	exporter := NewAuditTrailExporter("org-001")

	entries := []AuditEntry{
		{
			Timestamp: time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
			EventType: "ACCESS",
			Actor:     "admin",
			Resource:  "data",
			Action:    "READ",
			Outcome:   "ALLOWED",
		},
	}

	csv := exporter.ExportCSV(entries)
	require.Contains(t, csv, "timestamp,event_type,actor,resource,action,outcome")
	require.Contains(t, csv, "ACCESS,admin,data,READ,ALLOWED")
}

func TestSupportedFormats(t *testing.T) {
	exporter := NewAuditTrailExporter("org-001")
	formats := exporter.SupportedFormats()
	require.Len(t, formats, 4)
	require.Equal(t, "CEF", formats[0]) // Sorted
}

func TestComplianceFrameworkConstants(t *testing.T) {
	require.Equal(t, ComplianceFramework("MiCA"), FrameworkMiCA)
	require.Equal(t, ComplianceFramework("EU_AI_ACT"), FrameworkEUAIAct)
	require.Equal(t, ComplianceFramework("SOC2_TYPE_II"), FrameworkSOC2)
}

func TestAttestationStatusConstants(t *testing.T) {
	require.Equal(t, AttestationStatus("COMPLIANT"), StatusCompliant)
	require.Equal(t, AttestationStatus("NON_COMPLIANT"), StatusNonCompliant)
	require.Equal(t, AttestationStatus("PENDING_REVIEW"), StatusPending)
}

func TestAIRiskCategoryConstants(t *testing.T) {
	require.Equal(t, AIRiskCategory("MINIMAL"), RiskMinimal)
	require.Equal(t, AIRiskCategory("HIGH"), RiskHigh)
	require.Equal(t, AIRiskCategory("UNACCEPTABLE"), RiskUnacceptable)
}
