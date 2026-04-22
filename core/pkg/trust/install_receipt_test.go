package trust

import (
	"testing"
	"time"
)

func TestRecordInstall(t *testing.T) {
	reg := NewInstallRegistry()
	receipt, err := reg.RecordInstall("my-pack", "1.0.0", "sha256:abc", "t1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if receipt.PackName != "my-pack" {
		t.Fatal("expected my-pack")
	}
	if receipt.ContentHash == "" {
		t.Fatal("expected content hash")
	}
}

func TestInstallChaining(t *testing.T) {
	reg := NewInstallRegistry()
	r1, _ := reg.RecordInstall("my-pack", "1.0.0", "sha256:abc", "t1", "alice")
	r2, _ := reg.RecordInstall("my-pack", "2.0.0", "sha256:def", "t1", "alice")

	if r2.PrevReceiptID != r1.ReceiptID {
		t.Fatal("second receipt should chain to first")
	}
}

func TestRevocation(t *testing.T) {
	reg := NewInstallRegistry()
	reg.RecordInstall("bad-pack", "1.0.0", "sha256:evil", "t1", "alice")
	reg.Revoke("bad-pack")

	if !reg.IsRevoked("bad-pack") {
		t.Fatal("expected revoked")
	}

	_, err := reg.RecordInstall("bad-pack", "2.0.0", "sha256:evil2", "t1", "alice")
	if err == nil {
		t.Fatal("expected error installing revoked pack")
	}
}

func TestTrustScore(t *testing.T) {
	reg := NewInstallRegistry()
	reg.SetTrustScore(&PackTrustScore{
		PackName:   "good-pack",
		Score:      95.0,
		Certified:  true,
		AssessedAt: time.Now(),
	})

	score, err := reg.GetTrustScore("good-pack")
	if err != nil {
		t.Fatal(err)
	}
	if score.Score != 95.0 {
		t.Fatalf("expected 95.0, got %.1f", score.Score)
	}
}

func TestRevokedTrustScoreZero(t *testing.T) {
	reg := NewInstallRegistry()
	reg.SetTrustScore(&PackTrustScore{PackName: "bad", Score: 80.0})
	reg.Revoke("bad")

	score, _ := reg.GetTrustScore("bad")
	if score.Score != 0 {
		t.Fatal("revoked pack should have score 0")
	}
	if !score.Revoked {
		t.Fatal("expected revoked flag")
	}
}

func TestGetReceipt(t *testing.T) {
	reg := NewInstallRegistry()
	r, _ := reg.RecordInstall("p", "1.0", "sha256:a", "t1", "bob")

	got, err := reg.GetReceipt(r.ReceiptID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PackVersion != "1.0" {
		t.Fatal("version mismatch")
	}
}
