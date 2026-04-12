// Package tee provides hardware-rooted trust via Trusted Execution Environment
// (TEE) attestation. It defines a platform-agnostic Attestor interface with
// implementations for TPM 2.0, Intel TDX, and a simulated attestor for testing.
//
// AttestationReports bind governance decisions (via UserData) to hardware-verified
// platform measurements, making signatures unforgeable even with root access.
package tee

import "time"

// Platform identifies the TEE hardware platform.
type Platform string

const (
	PlatformIntelTDX  Platform = "INTEL_TDX"
	PlatformIntelSGX  Platform = "INTEL_SGX"
	PlatformAMDSEV    Platform = "AMD_SEV_SNP"
	PlatformTPM20     Platform = "TPM_2_0"
	PlatformSimulated Platform = "SIMULATED" // for testing
)

// AttestationReport is a hardware-generated proof of platform integrity.
// The report binds application-level data (e.g., a governance decision hash)
// to a hardware-attested platform measurement, providing tamper-evident proof
// that code ran in a verified execution environment.
type AttestationReport struct {
	ReportID        string    `json:"report_id"`
	Platform        Platform  `json:"platform"`
	PlatformData    string    `json:"platform_data"`    // platform-specific opaque data
	MeasurementHash string    `json:"measurement_hash"` // PCR/MRENCLAVE/MRTD digest
	Nonce           string    `json:"nonce"`             // anti-replay
	UserData        string    `json:"user_data"`         // application-embedded data (e.g., decision hash)
	Signature       string    `json:"signature"`         // platform key signature
	Certificate     string    `json:"certificate,omitempty"` // attestation key certificate chain
	GeneratedAt     time.Time `json:"generated_at"`
	ContentHash     string    `json:"content_hash"`
}

// AttestationResult is the output of verifying an attestation report.
type AttestationResult struct {
	Valid            bool     `json:"valid"`
	Platform         Platform `json:"platform"`
	Trusted          bool     `json:"trusted"`            // platform meets trust requirements
	MeasurementMatch bool     `json:"measurement_match"`  // expected measurement matches
	FreshnessValid   bool     `json:"freshness_valid"`    // nonce/timestamp acceptable
	Reason           string   `json:"reason,omitempty"`
}

// NonceFreshnessDuration is the maximum age of a nonce before it is considered stale.
const NonceFreshnessDuration = 5 * time.Minute
