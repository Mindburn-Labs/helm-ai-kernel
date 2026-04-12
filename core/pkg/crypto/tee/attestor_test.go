package tee

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

const testMeasurementHash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

func newTestAttestor(t *testing.T) (*SimulatedAttestor, crypto.Signer) {
	t.Helper()
	signer, err := crypto.NewEd25519Signer("test-tee-key")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	attestor := NewSimulatedAttestor(signer, testMeasurementHash)
	return attestor, signer
}

func TestSimulatedAttestor_Attest(t *testing.T) {
	attestor, _ := newTestAttestor(t)
	ctx := context.Background()

	userData := []byte("decision-hash-abc123")
	report, err := attestor.Attest(ctx, userData)
	if err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	if report.ReportID == "" {
		t.Error("expected non-empty report ID")
	}
	if report.Platform != PlatformSimulated {
		t.Errorf("expected platform SIMULATED, got %s", report.Platform)
	}
	if report.MeasurementHash != testMeasurementHash {
		t.Errorf("expected measurement hash %s, got %s", testMeasurementHash, report.MeasurementHash)
	}
	if report.Nonce == "" {
		t.Error("expected non-empty nonce")
	}
	if report.UserData != hex.EncodeToString(userData) {
		t.Errorf("expected user data %s, got %s", hex.EncodeToString(userData), report.UserData)
	}
	if report.Signature == "" {
		t.Error("expected non-empty signature")
	}
	if report.ContentHash == "" {
		t.Error("expected non-empty content hash")
	}
	if report.GeneratedAt.IsZero() {
		t.Error("expected non-zero generated_at timestamp")
	}
}

func TestSimulatedAttestor_Verify(t *testing.T) {
	attestor, _ := newTestAttestor(t)
	ctx := context.Background()

	userData := []byte("decision-hash-verify-test")
	report, err := attestor.Attest(ctx, userData)
	if err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	result, err := attestor.Verify(ctx, report)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid report, got reason: %s", result.Reason)
	}
	if !result.Trusted {
		t.Error("expected trusted result")
	}
	if !result.MeasurementMatch {
		t.Error("expected measurement match")
	}
	if !result.FreshnessValid {
		t.Error("expected freshness valid")
	}
	if result.Platform != PlatformSimulated {
		t.Errorf("expected platform SIMULATED, got %s", result.Platform)
	}
}

func TestSimulatedAttestor_VerifyTampered(t *testing.T) {
	attestor, _ := newTestAttestor(t)
	ctx := context.Background()

	report, err := attestor.Attest(ctx, []byte("original-data"))
	if err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	// Tamper with user data
	report.UserData = hex.EncodeToString([]byte("tampered-data"))

	result, err := attestor.Verify(ctx, report)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if result.Valid {
		t.Error("tampered report should not be valid")
	}
	if result.Reason == "" {
		t.Error("expected a reason for invalid report")
	}
}

func TestSimulatedAttestor_VerifyTamperedSignature(t *testing.T) {
	attestor, _ := newTestAttestor(t)
	ctx := context.Background()

	report, err := attestor.Attest(ctx, []byte("test-data"))
	if err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	// Tamper with signature
	report.Signature = "deadbeef" + report.Signature[8:]

	result, err := attestor.Verify(ctx, report)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if result.Valid {
		t.Error("tampered signature should not be valid")
	}
}

func TestSimulatedAttestor_VerifyWrongMeasurement(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("test-key")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Attestor expects one measurement hash
	attestor := NewSimulatedAttestor(signer, testMeasurementHash)
	ctx := context.Background()

	report, err := attestor.Attest(ctx, []byte("test-data"))
	if err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	// Verifier expects a different measurement hash
	verifier := NewSimulatedAttestor(signer, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

	result, err := verifier.Verify(ctx, report)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if result.Valid {
		t.Error("mismatched measurement should not be valid")
	}
	if result.MeasurementMatch {
		t.Error("expected measurement_match to be false")
	}
}

func TestSimulatedAttestor_VerifyExpiredNonce(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("test-key")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Attestor with a fixed clock in the past
	pastTime := time.Now().Add(-10 * time.Minute)
	pastAttestor := NewSimulatedAttestorWithClock(signer, testMeasurementHash, func() time.Time {
		return pastTime
	})

	ctx := context.Background()
	report, err := pastAttestor.Attest(ctx, []byte("test-data"))
	if err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	// Verifier uses current time (report is 10 minutes old, beyond 5-minute window)
	currentAttestor := NewSimulatedAttestor(signer, testMeasurementHash)

	result, err := currentAttestor.Verify(ctx, report)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if result.Valid {
		t.Error("expired nonce should not be valid")
	}
	if result.FreshnessValid {
		t.Error("expected freshness_valid to be false")
	}
}

func TestSimulatedAttestor_Platform(t *testing.T) {
	attestor, _ := newTestAttestor(t)
	if attestor.Platform() != PlatformSimulated {
		t.Errorf("expected SIMULATED, got %s", attestor.Platform())
	}
}

func TestAttestorInterface(t *testing.T) {
	attestor, _ := newTestAttestor(t)

	// Compile-time check that SimulatedAttestor implements Attestor
	var _ Attestor = attestor
}

func TestTPMAttestor_NoHardware(t *testing.T) {
	attestor := NewTPMAttestor("/dev/tpmrm0", 7)
	ctx := context.Background()

	if attestor.Platform() != PlatformTPM20 {
		t.Errorf("expected TPM_2_0, got %s", attestor.Platform())
	}

	_, err := attestor.Attest(ctx, []byte("test"))
	if err == nil {
		t.Error("expected error from TPM attestor without hardware")
	}

	_, err = attestor.Verify(ctx, &AttestationReport{})
	if err == nil {
		t.Error("expected error from TPM verifier without hardware")
	}

	// Verify TPMAttestor implements Attestor interface
	var _ Attestor = attestor
}

func TestIntelTDXAttestor_NoHardware(t *testing.T) {
	attestor := NewIntelTDXAttestor("https://trust-authority.example.com", "test-key")
	ctx := context.Background()

	if attestor.Platform() != PlatformIntelTDX {
		t.Errorf("expected INTEL_TDX, got %s", attestor.Platform())
	}

	_, err := attestor.Attest(ctx, []byte("test"))
	if err == nil {
		t.Error("expected error from Intel TDX attestor without hardware")
	}

	_, err = attestor.Verify(ctx, &AttestationReport{})
	if err == nil {
		t.Error("expected error from Intel TDX verifier without hardware")
	}

	// Verify IntelTDXAttestor implements Attestor interface
	var _ Attestor = attestor
}

func TestSimulatedAttestor_VerifyNilReport(t *testing.T) {
	attestor, _ := newTestAttestor(t)
	ctx := context.Background()

	_, err := attestor.Verify(ctx, nil)
	if err == nil {
		t.Error("expected error for nil report")
	}
}

func TestSimulatedAttestor_DifferentUserData(t *testing.T) {
	attestor, _ := newTestAttestor(t)
	ctx := context.Background()

	// Two reports with different user data should have different content hashes
	report1, err := attestor.Attest(ctx, []byte("data-one"))
	if err != nil {
		t.Fatalf("Attest 1 failed: %v", err)
	}

	report2, err := attestor.Attest(ctx, []byte("data-two"))
	if err != nil {
		t.Fatalf("Attest 2 failed: %v", err)
	}

	if report1.ContentHash == report2.ContentHash {
		t.Error("different user data should produce different content hashes")
	}

	// Each should verify independently
	result1, err := attestor.Verify(ctx, report1)
	if err != nil {
		t.Fatalf("Verify 1 failed: %v", err)
	}
	if !result1.Valid {
		t.Errorf("report 1 should be valid, reason: %s", result1.Reason)
	}

	result2, err := attestor.Verify(ctx, report2)
	if err != nil {
		t.Fatalf("Verify 2 failed: %v", err)
	}
	if !result2.Valid {
		t.Errorf("report 2 should be valid, reason: %s", result2.Reason)
	}
}
