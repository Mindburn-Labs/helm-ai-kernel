package tee

import (
	"context"
	"encoding/binary"
	"fmt"
	"runtime"
)

// AMD SEV-SNP attestation report format (ABI Specification, Rev 1.55, §7).
// The fixed-size report is 1184 bytes; the trailing 512 bytes are an
// ECDSA P-384 signature over the first 672 bytes (the body).
//
// Field offsets (subset; we only parse what the verifier needs):
//
//	offset  size  field
//	0       4     version            (u32, currently 2 or 3)
//	4       4     guest_svn          (u32)
//	8       8     policy             (u64)
//	16      16    family_id
//	32      16    image_id
//	48      4     vmpl               (u32)
//	52      4     signature_algo     (u32, 1 = ECDSA-P384-SHA384)
//	56      8     current_tcb        (u64)
//	64      8     platform_info      (u64)
//	72      4     author_key_en      (u32)
//	76      4     reserved
//	80      64    report_data        (nonce in first 32 bytes for HELM)
//	144     48    measurement        (TCB launch digest)
//	192     32    host_data
//	224     48    id_key_digest
//	272     48    author_key_digest
//	320     32    report_id
//	352     32    report_id_ma
//	384     8     reported_tcb
//	392     24    reserved
//	416     64    chip_id
//	480     8     committed_tcb
//	488     1     current_build
//	489     1     current_minor
//	490     1     current_major
//	...
//	672     512   signature (ECDSA P-384)
//
// The verifier consumes only version / report_data / measurement / chip_id and
// the trailing signature. Real verifier deployments also walk the Versioned
// Chip Endorsement Key (VCEK) chain to AMD KDS.
//
// References:
//   - AMD SEV-SNP ABI Specification (Rev 1.55), Chapter 7.
//   - https://github.com/AMDESE/sev-guest (reference user-space + ioctl wrappers).
//   - AMD Key Distribution Service (KDS): https://kdsintf.amd.com.

const (
	// SEVSNPReportSize is the total fixed size in bytes of an SEV-SNP
	// attestation report.
	SEVSNPReportSize = 1184

	// SEVSNPSignatureSize is the trailing signature blob size (ECDSA P-384).
	SEVSNPSignatureSize = 512

	// SEVSNPBodySize is the signed-body size (everything except the trailing
	// signature).
	SEVSNPBodySize = SEVSNPReportSize - SEVSNPSignatureSize

	// SEVSNPMeasurementSize is the size of the TCB launch measurement field.
	SEVSNPMeasurementSize = 48

	// SEVSNPReportDataSize is the size of the report_data field (the field that
	// holds the verifier-supplied nonce in its first 32 bytes).
	SEVSNPReportDataSize = 64

	// sevsnpReportDataOffset is the offset of report_data inside the report.
	sevsnpReportDataOffset = 80

	// sevsnpMeasurementOffset is the offset of measurement inside the report.
	sevsnpMeasurementOffset = 144

	// sevsnpChipIDOffset is the offset of chip_id inside the report.
	sevsnpChipIDOffset = 416

	// sevsnpVersionOffset is the offset of the version field.
	sevsnpVersionOffset = 0
)

// SEVSNPReport is a structured view over the bytes returned by the
// /dev/sev-guest ioctl interface.
type SEVSNPReport struct {
	Version     uint32
	ReportData  []byte // 64 bytes; nonce in first 32
	Measurement []byte // 48 bytes
	ChipID      []byte // 64 bytes
	Signature   []byte // 512 bytes (ECDSA P-384, ASN.1)
	Body        []byte // signed pre-image (672 bytes)
}

// ParseSEVSNPReport parses a raw SEV-SNP attestation report.
func ParseSEVSNPReport(raw []byte) (*SEVSNPReport, error) {
	if len(raw) != SEVSNPReportSize {
		return nil, fmt.Errorf("%w: SEV-SNP report size %d, expected %d", ErrMalformedQuote, len(raw), SEVSNPReportSize)
	}
	r := &SEVSNPReport{}
	r.Version = binary.LittleEndian.Uint32(raw[sevsnpVersionOffset : sevsnpVersionOffset+4])
	if r.Version < 2 || r.Version > 3 {
		return nil, fmt.Errorf("%w: SEV-SNP version %d outside [2,3]", ErrMalformedQuote, r.Version)
	}
	r.ReportData = make([]byte, SEVSNPReportDataSize)
	copy(r.ReportData, raw[sevsnpReportDataOffset:sevsnpReportDataOffset+SEVSNPReportDataSize])
	r.Measurement = make([]byte, SEVSNPMeasurementSize)
	copy(r.Measurement, raw[sevsnpMeasurementOffset:sevsnpMeasurementOffset+SEVSNPMeasurementSize])
	r.ChipID = make([]byte, 64)
	copy(r.ChipID, raw[sevsnpChipIDOffset:sevsnpChipIDOffset+64])
	r.Body = make([]byte, SEVSNPBodySize)
	copy(r.Body, raw[:SEVSNPBodySize])
	r.Signature = make([]byte, SEVSNPSignatureSize)
	copy(r.Signature, raw[SEVSNPBodySize:])
	return r, nil
}

// Nonce extracts the verifier-supplied nonce (first 32 bytes of report_data).
func (r *SEVSNPReport) Nonce() []byte {
	if r == nil || len(r.ReportData) < NonceSize {
		return nil
	}
	out := make([]byte, NonceSize)
	copy(out, r.ReportData[:NonceSize])
	return out
}

// SEVSNPAttester is the AMD SEV-SNP RemoteAttester implementation. On a real
// SEV-SNP guest it talks to /dev/sev-guest via the GUEST_REQ_GET_REPORT ioctl
// (linux/sev-guest.h). On any other host it returns ErrNoHardware.
type SEVSNPAttester struct {
	// devicePath defaults to "/dev/sev-guest". Override for tests.
	devicePath string

	// synthetic, when non-nil, makes this adapter return the synthetic raw
	// bytes instead of issuing the ioctl. Used by tests that craft
	// spec-conformant quotes without real hardware.
	synthetic *SyntheticSEVSNP
}

// SyntheticSEVSNP holds the inputs needed to build a spec-conformant
// SEV-SNP attestation report without TEE hardware. Tests use this to
// exercise the parser and verifier with deterministic byte sequences.
type SyntheticSEVSNP struct {
	Version     uint32
	Measurement [SEVSNPMeasurementSize]byte
	ChipID      [64]byte
	// Signature is appended verbatim. Real silicon emits ECDSA-P384 over the
	// body; tests can supply zeros and rely on AllowMock-style trust roots.
	Signature [SEVSNPSignatureSize]byte
}

// NewSEVSNPAttester returns a SEV-SNP attester. On hosts without the kernel
// device the returned attester's Quote() will return ErrNoHardware.
func NewSEVSNPAttester() *SEVSNPAttester {
	return &SEVSNPAttester{devicePath: "/dev/sev-guest"}
}

// NewSyntheticSEVSNPAttester returns an attester that builds a spec-conformant
// raw report from the supplied static fields. Test use only.
func NewSyntheticSEVSNPAttester(s *SyntheticSEVSNP) *SEVSNPAttester {
	return &SEVSNPAttester{synthetic: s, devicePath: "/dev/sev-guest"}
}

// Platform reports PlatformSEVSNP.
func (a *SEVSNPAttester) Platform() Platform { return PlatformSEVSNP }

// Measurement returns the synthetic measurement when configured, otherwise
// ErrNoHardware. Real hosts populate this by reading the report once and
// caching the field.
func (a *SEVSNPAttester) Measurement() ([]byte, error) {
	if a.synthetic != nil {
		out := make([]byte, SEVSNPMeasurementSize)
		copy(out, a.synthetic.Measurement[:])
		return out, nil
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("%w: SEV-SNP requires linux", ErrNoHardware)
	}
	// TODO: real ioctl on Linux SEV-SNP guest. The reference user-space at
	// https://github.com/AMDESE/sev-guest issues SNP_GET_REPORT with an
	// arbitrary user data buffer; the kernel returns the 1184-byte report.
	return nil, ErrNoHardware
}

// Quote returns a spec-conformant SEV-SNP attestation report. Synthetic mode
// builds the bytes from the supplied static fields and embeds nonce inside
// report_data. Real-hardware mode would call the SNP_GET_REPORT ioctl with
// nonce as user data.
func (a *SEVSNPAttester) Quote(_ context.Context, nonce []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("tee/sevsnp: nonce length %d, expected %d", len(nonce), NonceSize)
	}
	if a.synthetic != nil {
		return a.buildSyntheticReport(nonce), nil
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("%w: SEV-SNP requires linux", ErrNoHardware)
	}
	// TODO: real ioctl on Linux SEV-SNP guest.
	//
	// The Linux SEV-SNP guest driver exposes /dev/sev-guest. Issue
	// SNP_GET_REPORT (ioctl number 0xc0205300) with a struct
	// snp_report_req{user_data[64], vmpl} where user_data[0:32]=nonce and the
	// remaining bytes are zero. The kernel returns
	// struct snp_report_resp { u8 data[4000] } whose first 1184 bytes are the
	// attestation_report. Wrap with golang.org/x/sys/unix.IoctlSetInt or a
	// cgo-free syscall.Syscall6 path. See AMDESE/sev-guest for canonical code.
	return nil, ErrNoHardware
}

// buildSyntheticReport produces a 1184-byte SEV-SNP-shaped report whose body
// fields match the synthetic config and whose report_data first 32 bytes hold
// nonce. The signature blob is filled with the supplied bytes verbatim.
func (a *SEVSNPAttester) buildSyntheticReport(nonce []byte) []byte {
	buf := make([]byte, SEVSNPReportSize)
	binary.LittleEndian.PutUint32(buf[sevsnpVersionOffset:], a.synthetic.Version)
	// report_data: nonce in first 32 bytes.
	copy(buf[sevsnpReportDataOffset:sevsnpReportDataOffset+NonceSize], nonce)
	// measurement.
	copy(buf[sevsnpMeasurementOffset:sevsnpMeasurementOffset+SEVSNPMeasurementSize], a.synthetic.Measurement[:])
	// chip_id.
	copy(buf[sevsnpChipIDOffset:sevsnpChipIDOffset+64], a.synthetic.ChipID[:])
	// signature.
	copy(buf[SEVSNPBodySize:], a.synthetic.Signature[:])
	return buf
}
