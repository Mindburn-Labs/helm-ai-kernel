package tee

import (
	"context"
	"fmt"
)

// TPMAttestor interfaces with a TPM 2.0 module for hardware attestation.
// This is a placeholder for production TPM integration via go-tpm.
//
// In production, Attest generates a TPM 2.0 quote binding user data to PCR
// measurements, and Verify checks the quote signature against the endorsement
// key certificate chain.
type TPMAttestor struct {
	devicePath string // e.g., "/dev/tpmrm0"
	pcrIndex   int    // PCR register index for measurements
}

// NewTPMAttestor creates a TPM 2.0 attestor targeting the given device and PCR index.
func NewTPMAttestor(devicePath string, pcrIndex int) *TPMAttestor {
	return &TPMAttestor{
		devicePath: devicePath,
		pcrIndex:   pcrIndex,
	}
}

// Platform returns PlatformTPM20.
func (t *TPMAttestor) Platform() Platform { return PlatformTPM20 }

// Attest generates a TPM 2.0 quote binding the given user data to PCR measurements.
// Production: use go-tpm library to open the device, read PCR values, and generate
// a quote signed by the attestation key.
func (t *TPMAttestor) Attest(ctx context.Context, userData []byte) (*AttestationReport, error) {
	return nil, fmt.Errorf("tee: TPM 2.0 attestation requires hardware device %s; use SimulatedAttestor for testing", t.devicePath)
}

// Verify checks a TPM 2.0 attestation report by verifying the quote signature
// against the endorsement key certificate chain and validating PCR values.
func (t *TPMAttestor) Verify(ctx context.Context, report *AttestationReport) (*AttestationResult, error) {
	return nil, fmt.Errorf("tee: TPM 2.0 verification requires endorsement key certificate chain; use SimulatedAttestor for testing")
}
