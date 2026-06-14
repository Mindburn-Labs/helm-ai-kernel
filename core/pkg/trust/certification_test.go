package trust

import (
	"testing"
	"time"
)

func TestCertificationGatePass(t *testing.T) {
	g := NewCertificationGate()
	g.SetRequirement("production", CertProduction)
	if err := g.RecordCertification(&CertificationRecord{
		PackName: "deploy-factory", PackVersion: "1.0", Level: CertProduction,
		CertifiedBy: "qa", CertifiedAt: time.Now(), TestsPassed: 100, TestsTotal: 100,
	}); err != nil {
		t.Fatal(err)
	}

	err := g.CheckInstall("deploy-factory", "1.0", "production")
	if err != nil {
		t.Fatal(err)
	}
}

func TestCertificationGateFail(t *testing.T) {
	g := NewCertificationGate()
	g.SetRequirement("production", CertProduction)
	if err := g.RecordCertification(&CertificationRecord{
		PackName: "test-pack", PackVersion: "1.0", Level: CertBasic,
	}); err != nil {
		t.Fatal(err)
	}

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
	if err := g.RecordCertification(&CertificationRecord{
		PackName: "p", PackVersion: "1.0", Level: CertVerified,
		TestsPassed: 12, TestsTotal: 12,
	}); err != nil {
		t.Fatal(err)
	}

	r, err := g.GetCertification("p", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if r.Level != CertVerified {
		t.Fatalf("expected VERIFIED, got %s", r.Level)
	}
}

func TestCertificationRequiresTestEvidence(t *testing.T) {
	g := NewCertificationGate()

	t.Run("production_without_tests_rejected", func(t *testing.T) {
		if err := g.RecordCertification(&CertificationRecord{
			PackName: "no-tests", PackVersion: "1.0", Level: CertProduction,
			TestsTotal: 0,
		}); err == nil {
			t.Fatal("PRODUCTION with TestsTotal==0 must error")
		}
		if _, err := g.GetCertification("no-tests", "1.0"); err == nil {
			t.Fatal("rejected certification must not be stored")
		}
	})

	t.Run("verified_with_failures_rejected", func(t *testing.T) {
		if err := g.RecordCertification(&CertificationRecord{
			PackName: "failing", PackVersion: "1.0", Level: CertVerified,
			TestsPassed: 9, TestsTotal: 10,
		}); err == nil {
			t.Fatal("VERIFIED with failing tests must error")
		}
	})

	t.Run("basic_without_tests_allowed", func(t *testing.T) {
		if err := g.RecordCertification(&CertificationRecord{
			PackName: "basic", PackVersion: "1.0", Level: CertBasic,
		}); err != nil {
			t.Fatalf("BASIC does not require test evidence: %v", err)
		}
	})
}
