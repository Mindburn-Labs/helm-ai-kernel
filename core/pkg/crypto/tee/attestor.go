package tee

import "context"

// Attestor generates and verifies hardware attestation reports.
// Implementations bind application-level data (typically a governance decision
// hash) to a hardware-attested platform measurement. The Attest method produces
// a report; the Verify method checks its validity against expected measurements.
type Attestor interface {
	// Platform returns the hardware platform type.
	Platform() Platform

	// Attest generates an attestation report binding the given user data.
	// The userData is typically a SHA-256 hash of the governance decision being attested.
	Attest(ctx context.Context, userData []byte) (*AttestationReport, error)

	// Verify checks an attestation report's validity, including signature,
	// measurement hash, and nonce freshness.
	Verify(ctx context.Context, report *AttestationReport) (*AttestationResult, error)
}
