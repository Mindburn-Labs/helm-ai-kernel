package tee

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
)

// TrustRoots is the configuration the verifier uses to decide whether an
// attestation chain terminates at a recognized vendor root.
//
// Each platform has its own root set; they are loaded from
// core/pkg/trust/tee_roots.go (Workstream A4) and may rotate on the same
// schedule as the existing TUF/SLSA/Rekor roots.
//
// TrustRoots is intentionally a value-type — verifiers can fork the value to
// permit a stricter or looser policy without touching the caller's set.
type TrustRoots struct {
	// AMDKDSRoots holds the AMD Key Distribution Service root certificates
	// (DER-encoded) used to validate the VCEK chain attached to SEV-SNP
	// reports. https://kdsintf.amd.com.
	AMDKDSRoots [][]byte

	// IntelPCSRoots holds the Intel Provisioning Certification Service root
	// certificates (DER-encoded) used to validate TDX quote chains.
	// https://api.trustedservices.intel.com.
	IntelPCSRoots [][]byte

	// AWSNitroRoots holds the AWS Nitro Attestation PKI root certificates
	// (DER-encoded). The Nitro signing chain terminates at these.
	// https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html.
	AWSNitroRoots [][]byte

	// AzureAttestationRoots holds the Microsoft Azure Attestation Service
	// root certificates. Azure Confidential VMs expose attestation via MAA.
	AzureAttestationRoots [][]byte

	// MockPublicKeys lists Ed25519 public keys recognized as legitimate mock
	// attesters. Empty + AllowMock=false means mock quotes always fail.
	MockPublicKeys []ed25519.PublicKey

	// AllowMock, when true, lets Verify accept PlatformMock quotes if their
	// signature matches a key in MockPublicKeys. Production deployments must
	// set AllowMock=false.
	AllowMock bool

	// RequireSignedChain, when true, requires the verifier to validate the
	// vendor signature against the configured roots. Test-only deployments
	// can set this false to inspect quote bytes without cryptographic
	// validation. Production deployments must set RequireSignedChain=true.
	RequireSignedChain bool
}

// VerifyResult captures the structured outputs of a successful verification.
// On failure, callers receive an error and an empty/zero VerifyResult.
type VerifyResult struct {
	// Platform is the issuing TEE family.
	Platform Platform

	// Measurement is the TCB launch measurement extracted from the quote.
	// Operators compare this against the expected release SLSA provenance
	// hash to detect a tampered binary.
	Measurement []byte

	// Nonce is the verifier-supplied nonce extracted from the quote.
	// Equal to expectedNonce on success.
	Nonce []byte

	// ChainTrustedTo names the trust root the chain terminates at, e.g.
	// "amd-kds", "intel-pcs", "aws-nitro", "azure-mhsm", or "mock".
	ChainTrustedTo string

	// Warnings carries non-fatal advisories (e.g. older quote version) that
	// the operator may want to log but that do not fail verification.
	Warnings []string
}

// QuoteNonce derives the verifier-binding nonce for a receipt by hashing the
// receipt's pre-signature canonical form. The receipt is identified to the
// verifier via this 32-byte digest; replays against any other receipt fail
// the nonce-match check.
//
// The pre-signature canonical form is the JSON-stable serialization of the
// receipt with the Signature and TEEAttestation fields stripped. Callers
// already produce that form when computing the receipt's content hash.
func QuoteNonce(canonicalReceiptBytes []byte) []byte {
	h := sha256.Sum256(canonicalReceiptBytes)
	out := make([]byte, NonceSize)
	copy(out, h[:])
	return out
}

// Verify validates a vendor-format quote against expectedNonce and roots.
// The verifier dispatches on the platform claimed by the caller.
//
// Successful return guarantees:
//
//  1. The quote bytes parse against the vendor specification.
//  2. The nonce in the quote equals expectedNonce.
//  3. (When RequireSignedChain) The signature in the quote validates against
//     a recognized root in TrustRoots.
//
// On any failure Verify returns an error wrapping one of the package's
// sentinel errors so callers can branch with errors.Is.
func Verify(platform Platform, raw []byte, expectedNonce []byte, roots TrustRoots) (*VerifyResult, error) {
	if len(expectedNonce) != NonceSize {
		return nil, fmt.Errorf("tee: expected nonce length %d, got %d", NonceSize, len(expectedNonce))
	}
	switch platform {
	case PlatformSEVSNP:
		return verifySEVSNP(raw, expectedNonce, roots)
	case PlatformTDX:
		return verifyTDX(raw, expectedNonce, roots)
	case PlatformNitro:
		return verifyNitro(raw, expectedNonce, roots)
	case PlatformMock:
		return verifyMock(raw, expectedNonce, roots)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownPlatform, platform)
	}
}

func verifySEVSNP(raw []byte, expectedNonce []byte, roots TrustRoots) (*VerifyResult, error) {
	report, err := ParseSEVSNPReport(raw)
	if err != nil {
		return nil, err
	}
	if !bytesEqual(report.Nonce(), expectedNonce) {
		return nil, ErrNonceMismatch
	}
	res := &VerifyResult{
		Platform:    PlatformSEVSNP,
		Measurement: report.Measurement,
		Nonce:       report.Nonce(),
	}
	if roots.RequireSignedChain {
		if len(roots.AMDKDSRoots) == 0 {
			return nil, fmt.Errorf("%w: no AMD KDS roots configured", ErrChainUntrusted)
		}
		// Follow-up: real ECDSA-P384 validation of report.Signature over report.Body
		// against the VCEK chain rooted in roots.AMDKDSRoots. Reference:
		// https://github.com/google/go-sev-guest. Until that lands the
		// strict path returns ErrChainUntrusted so deployments cannot opt
		// into a half-baked verification.
		return nil, fmt.Errorf("%w: SEV-SNP chain validation pending hardware test surface", ErrChainUntrusted)
	}
	res.Warnings = append(res.Warnings, "tee/sevsnp: chain validation skipped (RequireSignedChain=false)")
	res.ChainTrustedTo = "amd-kds-unverified"
	return res, nil
}

func verifyTDX(raw []byte, expectedNonce []byte, roots TrustRoots) (*VerifyResult, error) {
	q, err := ParseTDXQuote(raw)
	if err != nil {
		return nil, err
	}
	if !bytesEqual(q.Nonce(), expectedNonce) {
		return nil, ErrNonceMismatch
	}
	res := &VerifyResult{
		Platform:    PlatformTDX,
		Measurement: q.MRTD,
		Nonce:       q.Nonce(),
	}
	if roots.RequireSignedChain {
		if len(roots.IntelPCSRoots) == 0 {
			return nil, fmt.Errorf("%w: no Intel PCS roots configured", ErrChainUntrusted)
		}
		// Follow-up: real ECDSA-P256 validation of TDX quote against the QE chain
		// rooted in roots.IntelPCSRoots. Reference:
		// https://github.com/google/go-tdx-guest.
		return nil, fmt.Errorf("%w: TDX chain validation pending hardware test surface", ErrChainUntrusted)
	}
	res.Warnings = append(res.Warnings, "tee/tdx: chain validation skipped (RequireSignedChain=false)")
	res.ChainTrustedTo = "intel-pcs-unverified"
	return res, nil
}

func verifyNitro(raw []byte, expectedNonce []byte, roots TrustRoots) (*VerifyResult, error) {
	d, err := ParseNitroDocument(raw)
	if err != nil {
		return nil, err
	}
	if !bytesEqual(d.Nonce, expectedNonce) {
		return nil, ErrNonceMismatch
	}
	res := &VerifyResult{
		Platform:    PlatformNitro,
		Measurement: d.Measurement(),
		Nonce:       d.Nonce,
	}
	if roots.RequireSignedChain {
		if len(roots.AWSNitroRoots) == 0 {
			return nil, fmt.Errorf("%w: no AWS Nitro roots configured", ErrChainUntrusted)
		}
		// Follow-up: real COSE_Sign1 validation of d.Signature against the AWS
		// Nitro Attestation PKI rooted in roots.AWSNitroRoots.
		return nil, fmt.Errorf("%w: Nitro chain validation pending hardware test surface", ErrChainUntrusted)
	}
	res.Warnings = append(res.Warnings, "tee/nitro: chain validation skipped (RequireSignedChain=false)")
	res.ChainTrustedTo = "aws-nitro-unverified"
	return res, nil
}

func verifyMock(raw []byte, expectedNonce []byte, roots TrustRoots) (*VerifyResult, error) {
	if !roots.AllowMock {
		return nil, fmt.Errorf("%w: mock platform refused (AllowMock=false)", ErrChainUntrusted)
	}
	if len(roots.MockPublicKeys) == 0 {
		return nil, fmt.Errorf("%w: no mock public keys configured", ErrChainUntrusted)
	}
	measurement, _, _, err := ParseMockQuote(raw)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, pub := range roots.MockPublicKeys {
		if verr := VerifyMockQuote(raw, expectedNonce, pub); verr == nil {
			return &VerifyResult{
				Platform:       PlatformMock,
				Measurement:    measurement,
				Nonce:          expectedNonce,
				ChainTrustedTo: "mock",
			}, nil
		} else {
			lastErr = verr
			if errors.Is(verr, ErrNonceMismatch) {
				return nil, verr
			}
		}
	}
	if lastErr == nil {
		lastErr = ErrChainUntrusted
	}
	return nil, fmt.Errorf("tee/mock: no configured public key verifies quote: %w", lastErr)
}

// MeasurementMatches is a helper for receipt-time policy: does the quote's
// measurement equal expected? Operators set expected to the SHA-256/SHA-384 of
// the SLSA-provenanced release binary so a tampered binary cannot satisfy a
// --require-tee verification.
func MeasurementMatches(measurement, expected []byte) bool {
	if len(measurement) == 0 || len(expected) == 0 {
		return false
	}
	return bytesEqual(measurement, expected)
}
