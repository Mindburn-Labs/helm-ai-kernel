package tee

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

// SimulatedAttestor provides a software-only attestation for testing and development.
// It generates reports that mirror the structure of hardware attestation but use
// Ed25519 signing. This must never be used in production.
type SimulatedAttestor struct {
	signer          crypto.Signer
	measurementHash string
	clock           func() time.Time
}

// NewSimulatedAttestor creates a simulated attestor backed by an Ed25519 signer.
// The measurementHash represents the expected platform measurement digest; in
// production this would be a PCR, MRENCLAVE, or MRTD value.
func NewSimulatedAttestor(signer crypto.Signer, measurementHash string) *SimulatedAttestor {
	return &SimulatedAttestor{
		signer:          signer,
		measurementHash: measurementHash,
		clock:           time.Now,
	}
}

// NewSimulatedAttestorWithClock creates a simulated attestor with a custom clock.
// This is useful for deterministic testing of nonce freshness checks.
func NewSimulatedAttestorWithClock(signer crypto.Signer, measurementHash string, clock func() time.Time) *SimulatedAttestor {
	return &SimulatedAttestor{
		signer:          signer,
		measurementHash: measurementHash,
		clock:           clock,
	}
}

// Platform returns PlatformSimulated.
func (s *SimulatedAttestor) Platform() Platform { return PlatformSimulated }

// Attest generates a simulated attestation report binding the given userData.
// It creates a nonce, computes a content hash over the measurement, nonce, and
// user data, then signs the content hash with the Ed25519 signer.
func (s *SimulatedAttestor) Attest(ctx context.Context, userData []byte) (*AttestationReport, error) {
	// Generate 16-byte random nonce
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("tee: nonce generation failed: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	// Generate report ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("tee: report ID generation failed: %w", err)
	}
	reportID := hex.EncodeToString(idBytes)

	now := s.clock()
	userDataHex := hex.EncodeToString(userData)

	// Content hash: SHA-256(measurementHash || nonce || userData)
	contentHash := computeContentHash(s.measurementHash, nonce, userDataHex)

	// Sign the content hash
	sig, err := s.signer.Sign([]byte(contentHash))
	if err != nil {
		return nil, fmt.Errorf("tee: signing failed: %w", err)
	}

	report := &AttestationReport{
		ReportID:        reportID,
		Platform:        PlatformSimulated,
		PlatformData:    "simulated-tee-v1",
		MeasurementHash: s.measurementHash,
		Nonce:           nonce,
		UserData:        userDataHex,
		Signature:       sig,
		GeneratedAt:     now,
		ContentHash:     contentHash,
	}

	return report, nil
}

// Verify checks a simulated attestation report's validity. It verifies the
// Ed25519 signature, checks the measurement hash matches the expected value,
// and validates the nonce freshness (within NonceFreshnessDuration).
func (s *SimulatedAttestor) Verify(ctx context.Context, report *AttestationReport) (*AttestationResult, error) {
	if report == nil {
		return nil, fmt.Errorf("tee: nil report")
	}

	// Build the complete result upfront so all fields are set regardless of exit path.
	result := &AttestationResult{
		Platform:         report.Platform,
		Valid:            false,
		Trusted:          false,
		MeasurementMatch: false,
		FreshnessValid:   false,
	}

	// Check platform
	if report.Platform != PlatformSimulated {
		result.Reason = fmt.Sprintf("expected platform SIMULATED, got %s", report.Platform)
		return result, nil
	}

	// Verify content hash
	expectedHash := computeContentHash(report.MeasurementHash, report.Nonce, report.UserData)
	if report.ContentHash != expectedHash {
		result.Reason = "content hash mismatch"
		return result, nil
	}

	// Verify signature over content hash
	pubKeyHex := s.signer.PublicKey()
	valid, err := crypto.Verify(pubKeyHex, report.Signature, []byte(report.ContentHash))
	if err != nil {
		return nil, fmt.Errorf("tee: signature verification error: %w", err)
	}
	if !valid {
		result.Reason = "invalid signature"
		return result, nil
	}

	// Check measurement hash matches expected
	result.MeasurementMatch = report.MeasurementHash == s.measurementHash
	if !result.MeasurementMatch {
		result.Reason = fmt.Sprintf("measurement mismatch: got %s, want %s", report.MeasurementHash, s.measurementHash)
		return result, nil
	}

	// Check nonce freshness
	age := s.clock().Sub(report.GeneratedAt)
	result.FreshnessValid = age <= NonceFreshnessDuration && age >= 0
	if !result.FreshnessValid {
		result.Reason = fmt.Sprintf("nonce expired: age %s exceeds %s", age, NonceFreshnessDuration)
		return result, nil
	}

	result.Valid = true
	result.Trusted = true
	return result, nil
}

// computeContentHash produces SHA-256(measurementHash || nonce || userData)
// using JCS canonicalization for deterministic cross-platform hashing.
func computeContentHash(measurementHash, nonce, userData string) string {
	// Use JCS canonical form for deterministic hashing
	payload := struct {
		MeasurementHash string `json:"measurement_hash"`
		Nonce           string `json:"nonce"`
		UserData        string `json:"user_data"`
	}{
		MeasurementHash: measurementHash,
		Nonce:           nonce,
		UserData:        userData,
	}

	canonical, err := canonicalize.JCS(payload)
	if err != nil {
		// Fallback to simple concatenation if JCS fails (should not happen with string fields)
		h := sha256.Sum256([]byte(measurementHash + nonce + userData))
		return hex.EncodeToString(h[:])
	}

	h := sha256.Sum256(canonical)
	return hex.EncodeToString(h[:])
}
