package tee

import (
	"context"
	"fmt"
)

// IntelTDXAttestor interfaces with Intel Trust Domain Extensions (TDX) for
// hardware attestation. This is a placeholder for production integration via
// the Intel Trust Authority API.
//
// In production, Attest generates a TDX report binding user data to the TD
// measurement register (MRTD), and Verify checks the report signature against
// Intel's attestation service.
type IntelTDXAttestor struct {
	trustAuthorityURL string // Intel Trust Authority API endpoint
	apiKey            string // API key for Trust Authority
}

// NewIntelTDXAttestor creates an Intel TDX attestor targeting the given Trust Authority endpoint.
func NewIntelTDXAttestor(trustAuthorityURL, apiKey string) *IntelTDXAttestor {
	return &IntelTDXAttestor{
		trustAuthorityURL: trustAuthorityURL,
		apiKey:            apiKey,
	}
}

// Platform returns PlatformIntelTDX.
func (i *IntelTDXAttestor) Platform() Platform { return PlatformIntelTDX }

// Attest generates an Intel TDX report binding the given user data to the TD
// measurement register. Production: call the TDX guest driver to generate a
// TD report, then submit to Intel Trust Authority for signing.
func (i *IntelTDXAttestor) Attest(ctx context.Context, userData []byte) (*AttestationReport, error) {
	return nil, fmt.Errorf("tee: Intel TDX attestation requires TDX-enabled hardware and Trust Authority at %s; use SimulatedAttestor for testing", i.trustAuthorityURL)
}

// Verify checks an Intel TDX attestation report by validating the report
// signature against Intel Trust Authority and checking MRTD values.
func (i *IntelTDXAttestor) Verify(ctx context.Context, report *AttestationReport) (*AttestationResult, error) {
	return nil, fmt.Errorf("tee: Intel TDX verification requires Trust Authority at %s; use SimulatedAttestor for testing", i.trustAuthorityURL)
}
