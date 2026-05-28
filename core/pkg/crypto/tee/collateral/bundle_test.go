package collateral

import (
	"testing"
	"time"
)

func TestValidateOfflineBundleFixture(t *testing.T) {
	bundle, err := Load("testdata/offline_bundle.json")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if err := Validate(bundle, time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestValidateRejectsDigestMismatch(t *testing.T) {
	bundle, err := Load("testdata/offline_bundle.json")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	bundle.Documents[0].Body = "tampered"
	if err := Validate(bundle, time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("Validate() succeeded for tampered bundle")
	}
}

func TestValidateRejectsExpiredCollateral(t *testing.T) {
	bundle, err := Load("testdata/offline_bundle.json")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if err := Validate(bundle, time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("Validate() succeeded for expired bundle")
	}
}
