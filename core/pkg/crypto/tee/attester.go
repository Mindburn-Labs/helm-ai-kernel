// Package tee provides Trusted Execution Environment (TEE) remote attestation
// for HELM. It defines a vendor-agnostic RemoteAttester interface plus adapters
// for AMD SEV-SNP, Intel TDX, and AWS Nitro Enclaves, alongside a deterministic
// mock attester for non-TEE development and a verifier that walks vendor-specific
// quote chains to recognized trust roots.
//
// Design (Workstream A, helm-oss SOTA plan):
//
//   - The kernel binds every TEE quote to a single receipt. The quote nonce is
//     SHA-256 of the receipt's pre-signature canonical form. This makes the
//     quote replay-safe: a quote captured for receipt A can never satisfy
//     verification of receipt B.
//
//   - Each platform adapter implements RemoteAttester. The interface is small
//     on purpose — Quote, Platform, Measurement — so kernels can swap adapters
//     without touching call sites.
//
//   - The verifier is vendor-agnostic. It dispatches on Platform() and checks
//     the quote against the configured TrustRoots (AMD KDS, Intel PCS, AWS
//     Nitro PCR roots, Microsoft Azure Attestation). Verification has three
//     stages: (1) parse the vendor quote, (2) re-derive the expected nonce
//     and compare, (3) walk the embedded chain to a trusted root.
//
//   - Real-hardware enrollment requires a Linux host that exposes the
//     SEV-SNP / TDX / Nitro guest device (ioctl interfaces). On a non-TEE host
//     the platform adapters return ErrNoHardware. The mock attester carries the
//     development surface so non-TEE contributors are not blocked.
//
// References:
//
//   - AMD SEV-SNP ABI Specification (Rev 1.55): "SEV Secure Nested Paging
//     Firmware ABI Specification", Chapter 7 (Attestation Report Format).
//     https://www.amd.com/system/files/TechDocs/56860.pdf
//   - Intel TDX Module v1.5 Architecture: TDREPORT / TDQUOTE format,
//     "Intel Trust Domain Extensions" Section 22.
//     https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html
//   - AWS Nitro Enclaves: NSM API, COSE_Sign1 attestation document format.
//     https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html
package tee

import (
	"context"
	"errors"
	"fmt"
)

// Platform identifies the TEE family producing or verifying a quote.
type Platform string

const (
	// PlatformSEVSNP identifies AMD SEV-SNP guests.
	PlatformSEVSNP Platform = "sevsnp"

	// PlatformTDX identifies Intel TDX trust domains.
	PlatformTDX Platform = "tdx"

	// PlatformNitro identifies AWS Nitro Enclaves.
	PlatformNitro Platform = "nitro"

	// PlatformMock identifies the deterministic mock attester used by the
	// dev/test loop on non-TEE hosts.
	PlatformMock Platform = "mock"
)

// NonceSize is the size of the quote nonce in bytes (SHA-256 digest).
const NonceSize = 32

// Sentinel errors. Callers can errors.Is against these to branch.
var (
	// ErrNoHardware is returned by a real platform adapter when its kernel
	// device (e.g. /dev/sev-guest) is not present, e.g. when running on a
	// non-TEE host. Operator code should fall back to the mock attester or
	// fail loudly depending on the deployment policy.
	ErrNoHardware = errors.New("tee: TEE hardware not available on this host")

	// ErrNonceMismatch is returned by Verify when the quote's nonce does not
	// match the expected nonce. This is the primary replay-safety check.
	ErrNonceMismatch = errors.New("tee: quote nonce does not match expected nonce")

	// ErrUnknownPlatform is returned by the verifier when a quote claims a
	// platform that has no registered handler.
	ErrUnknownPlatform = errors.New("tee: unknown platform")

	// ErrChainUntrusted is returned by Verify when the quote's certificate
	// chain does not terminate at a trusted root.
	ErrChainUntrusted = errors.New("tee: quote chain does not terminate at a trusted root")

	// ErrMalformedQuote is returned when a quote does not parse against the
	// vendor specification.
	ErrMalformedQuote = errors.New("tee: malformed vendor quote")
)

// RemoteAttester is the vendor-agnostic interface every TEE adapter implements.
// Implementations are expected to be cheap to construct (the kernel may rebuild
// one per receipt) and safe for concurrent use across goroutines.
type RemoteAttester interface {
	// Quote produces a vendor-format attestation quote bound to nonce.
	// The nonce is typically SHA-256 of the receipt's pre-signature canonical
	// form, which gives every quote single-use semantics.
	//
	// Quote returns the raw vendor quote bytes (e.g. an SEV-SNP attestation
	// report, a TDX TDQUOTE, or a Nitro COSE_Sign1 document). The returned
	// bytes are opaque at this layer; the verifier knows how to parse them.
	Quote(ctx context.Context, nonce []byte) ([]byte, error)

	// Platform returns the TEE family this attester serves.
	Platform() Platform

	// Measurement returns the attester's TCB launch measurement (e.g.
	// SEV-SNP MEASUREMENT field, TDX MRTD, Nitro PCR0..2). The shape is
	// vendor-specific but always a fixed-length digest.
	Measurement() ([]byte, error)
}

// Quote is a structured wrapper around a raw vendor quote. The kernel embeds
// this in receipts and evidence packs; verifiers consume it directly.
type Quote struct {
	// Platform identifies the issuing TEE family.
	Platform Platform `json:"platform"`

	// Raw is the opaque vendor-format quote bytes (SEV-SNP report, TDX TDQUOTE,
	// Nitro COSE_Sign1).
	Raw []byte `json:"raw"`

	// Measurement is the TCB launch measurement embedded in the quote (e.g.
	// SEV-SNP MEASUREMENT, TDX MRTD, or concatenated Nitro PCR0..PCR2).
	Measurement []byte `json:"measurement"`

	// Nonce is the value the verifier expects to find inside the vendor quote.
	// Bound to the receipt's pre-signature canonical form by the kernel.
	Nonce []byte `json:"nonce"`

	// Chain is the optional vendor certificate chain that proves the quote is
	// signed by genuine vendor silicon. Format depends on Platform.
	Chain [][]byte `json:"chain,omitempty"`
}

// String returns a short human-readable representation of the quote.
func (q *Quote) String() string {
	if q == nil {
		return "<nil quote>"
	}
	return fmt.Sprintf("tee.Quote{platform=%s rawSize=%d measurement=%dB nonce=%dB chain=%d}",
		q.Platform, len(q.Raw), len(q.Measurement), len(q.Nonce), len(q.Chain))
}

// ValidateBasic does a structural sanity check on a quote. It does not perform
// cryptographic verification — that is the verifier's job.
func (q *Quote) ValidateBasic() error {
	if q == nil {
		return fmt.Errorf("tee: quote is nil")
	}
	if q.Platform == "" {
		return fmt.Errorf("tee: quote has empty platform")
	}
	if len(q.Raw) == 0 {
		return fmt.Errorf("tee: quote raw is empty")
	}
	if len(q.Nonce) != NonceSize {
		return fmt.Errorf("tee: quote nonce length is %d, expected %d", len(q.Nonce), NonceSize)
	}
	return nil
}
