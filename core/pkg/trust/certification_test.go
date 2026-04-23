package trust

import (
	"testing"
	"time"
)

func TestCertificationGatePass(t *testing.T) {
	g := NewCertificationGate()
	g.SetRequirement("production", CertProduction)
	g.RecordCertification(&CertificationRecord{
		PackName: "deploy-factory", PackVersion: "1.0", Level: CertProduction,
		CertifiedBy: "qa", CertifiedAt: time.Now(), TestsPassed: 100, TestsTotal: 100,
	})

	err := g.CheckInstall("deploy-factory", "1.0", "production")
	if err != nil {
		t.Fatal(err)
	}
}

func TestCertificationGateFail(t *testing.T) {
	g := NewCertificationGate()
	g.SetRequirement("production", CertProduction)
	g.RecordCertification(&CertificationRecord{
		PackName: "test-pack", PackVersion: "1.0", Level: CertBasic,
	})

	err := g.CheckInstall("test-pack", "1.0", "production")
	if err == nil {
		t.Fatal("expected error: BASIC < PRODUCTION")
	}
}

func TestCertificationGateNoCert(t *testing.T) {
	g := NewCertificationGate()
	err := g.CheckInstall("unknown", "1.0", "staging")
	if err == nil {
		t.Fatal("expected error for uncertified pack")
	}
}

func TestCertificationGetRecord(t *testing.T) {
	g := NewCertificationGate()
	g.RecordCertification(&CertificationRecord{PackName: "p", PackVersion: "1.0", Level: CertVerified})

	r, err := g.GetCertification("p", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if r.Level != CertVerified {
		t.Fatalf("expected VERIFIED, got %s", r.Level)
	}
}
