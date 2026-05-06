package tee

import (
	"context"
	"encoding/binary"
	"fmt"
	"runtime"
)

// Intel TDX quote format (DCAP Quote v4, used by TDX Module v1.5+).
//
// A TDX quote is a TEE_quote_v4 wrapping a TDREPORT_BODY. The signed bytes
// cover the 48-byte header plus the 584-byte TDREPORT body. Trailing data
// is the ECDSA-P256 signature plus the QE Report and signature chain that
// terminates at Intel PCS-issued certificates.
//
// Field offsets used by the verifier:
//
//	header (48 bytes)
//	  0    2  version              (u16, == 4)
//	  2    2  att_key_type         (u16, 2 = ECDSA-P256-with-P256)
//	  4    4  tee_type             (u32, 0x00000081 = TDX)
//	  8    4  reserved
//	  12   16 qe_vendor_id
//	  28   20 user_data            (Intel-defined; verifier ignores)
//
//	tdreport_body (584 bytes, starting at offset 48)
//	  0    16  tee_tcb_svn
//	  16   48  mr_seam               (TDX module measurement)
//	  64   48  mrsigner_seam
//	  112  8   seam_attributes
//	  120  8   td_attributes
//	  128  8   xfam
//	  136  48  mr_td                 (TD launch measurement; this is what HELM cares about)
//	  184  48  mr_config_id
//	  232  48  mr_owner
//	  280  48  mr_owner_config
//	  328  48  rtmr0
//	  376  48  rtmr1
//	  424  48  rtmr2
//	  472  48  rtmr3
//	  520  64  report_data           (nonce in first 32 bytes for HELM)
//
// References:
//   - Intel TDX Module v1.5 ABI Spec, "TDREPORT".
//   - Intel SGX DCAP Quoting v4 (the TEE_quote_v4 wrapper):
//     https://github.com/intel/SGXDataCenterAttestationPrimitives.
//   - Intel Provisioning Certification Service (PCS):
//     https://api.trustedservices.intel.com.

const (
	// TDXHeaderSize is the size of the TEE_quote_v4 header.
	TDXHeaderSize = 48

	// TDXBodySize is the size of the embedded TDREPORT body.
	TDXBodySize = 584

	// TDXSignedSize is the body bytes covered by the ECDSA signature.
	TDXSignedSize = TDXHeaderSize + TDXBodySize

	// TDXMRTDSize is the size of the MRTD field (TD launch measurement).
	TDXMRTDSize = 48

	// TDXReportDataSize is the size of report_data (the field that holds the
	// verifier-supplied nonce in its first 32 bytes).
	TDXReportDataSize = 64

	// tdxVersionOffset / tdxTeeTypeOffset for the header.
	tdxVersionOffset = 0
	tdxTeeTypeOffset = 4

	// tdxMRTDOffset is the offset of mr_td inside the TDREPORT body.
	tdxMRTDOffset = 136

	// tdxReportDataOffset is the offset of report_data inside the body.
	tdxReportDataOffset = 520

	// TDXTeeTypeTDX is the tee_type constant identifying a TDX quote.
	TDXTeeTypeTDX uint32 = 0x00000081

	// minimum trailing signature blob; real Intel quotes ship far more
	// (ECDSA sig, QE report, certs). We accept any size >= this minimum.
	tdxMinSignatureBlobSize = 64
)

// TDXQuote is a structured view over an Intel TDX DCAP v4 quote.
type TDXQuote struct {
	Version    uint16
	TeeType    uint32
	MRTD       []byte // 48 bytes
	ReportData []byte // 64 bytes
	Signature  []byte // trailing variable-size signature + QE chain
	Body       []byte // header || TDREPORT body (signed pre-image, 632 bytes)
}

// ParseTDXQuote parses a TDX DCAP v4 quote.
func ParseTDXQuote(raw []byte) (*TDXQuote, error) {
	if len(raw) < TDXSignedSize+tdxMinSignatureBlobSize {
		return nil, fmt.Errorf("%w: TDX quote size %d, minimum %d", ErrMalformedQuote, len(raw), TDXSignedSize+tdxMinSignatureBlobSize)
	}
	q := &TDXQuote{}
	q.Version = binary.LittleEndian.Uint16(raw[tdxVersionOffset:])
	if q.Version != 4 {
		return nil, fmt.Errorf("%w: TDX quote version %d, expected 4", ErrMalformedQuote, q.Version)
	}
	q.TeeType = binary.LittleEndian.Uint32(raw[tdxTeeTypeOffset:])
	if q.TeeType != TDXTeeTypeTDX {
		return nil, fmt.Errorf("%w: TDX tee_type 0x%08x, expected 0x%08x", ErrMalformedQuote, q.TeeType, TDXTeeTypeTDX)
	}
	body := raw[TDXHeaderSize : TDXHeaderSize+TDXBodySize]
	q.MRTD = make([]byte, TDXMRTDSize)
	copy(q.MRTD, body[tdxMRTDOffset:tdxMRTDOffset+TDXMRTDSize])
	q.ReportData = make([]byte, TDXReportDataSize)
	copy(q.ReportData, body[tdxReportDataOffset:tdxReportDataOffset+TDXReportDataSize])
	q.Body = make([]byte, TDXSignedSize)
	copy(q.Body, raw[:TDXSignedSize])
	q.Signature = make([]byte, len(raw)-TDXSignedSize)
	copy(q.Signature, raw[TDXSignedSize:])
	return q, nil
}

// Nonce extracts the verifier-supplied nonce (first 32 bytes of report_data).
func (q *TDXQuote) Nonce() []byte {
	if q == nil || len(q.ReportData) < NonceSize {
		return nil
	}
	out := make([]byte, NonceSize)
	copy(out, q.ReportData[:NonceSize])
	return out
}

// TDXAttester is the Intel TDX RemoteAttester implementation.
type TDXAttester struct {
	devicePath string
	synthetic  *SyntheticTDX
}

// SyntheticTDX holds the inputs to build a spec-conformant TDX quote without
// hardware. Tests use this to exercise the parser and verifier.
type SyntheticTDX struct {
	MRTD             [TDXMRTDSize]byte
	SignatureBlob    []byte // appended verbatim; tests may use any non-empty bytes >= 64
	OmitTeeTypeMatch bool   // when true, write a wrong tee_type for negative tests
	OverrideVersion  uint16 // when non-zero, write that version for negative tests
}

// NewTDXAttester returns a TDX attester. On hosts without /dev/tdx_guest the
// returned attester's Quote() will return ErrNoHardware.
func NewTDXAttester() *TDXAttester {
	return &TDXAttester{devicePath: "/dev/tdx_guest"}
}

// NewSyntheticTDXAttester returns an attester that builds a spec-conformant
// raw quote from the supplied static fields. Test use only.
func NewSyntheticTDXAttester(s *SyntheticTDX) *TDXAttester {
	return &TDXAttester{synthetic: s, devicePath: "/dev/tdx_guest"}
}

// Platform reports PlatformTDX.
func (a *TDXAttester) Platform() Platform { return PlatformTDX }

// Measurement returns the synthetic MRTD when configured, otherwise
// ErrNoHardware.
func (a *TDXAttester) Measurement() ([]byte, error) {
	if a.synthetic != nil {
		out := make([]byte, TDXMRTDSize)
		copy(out, a.synthetic.MRTD[:])
		return out, nil
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("%w: TDX requires linux", ErrNoHardware)
	}
	// Follow-up: real ioctl on Linux TDX guest.
	return nil, ErrNoHardware
}

// Quote returns a spec-conformant TDX DCAP v4 quote. Synthetic mode embeds
// nonce inside report_data and copies the synthetic MRTD into mr_td.
func (a *TDXAttester) Quote(_ context.Context, nonce []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("tee/tdx: nonce length %d, expected %d", len(nonce), NonceSize)
	}
	if a.synthetic != nil {
		return a.buildSyntheticQuote(nonce), nil
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("%w: TDX requires linux", ErrNoHardware)
	}
	// Follow-up: real ioctl on Linux TDX guest.
	//
	// The Linux TDX guest driver exposes /dev/tdx_guest. The TDX guest tools
	// reference (https://github.com/intel/tdx-tools) issues
	// TDX_CMD_GET_QUOTE with a tdx_quote_hdr that includes report_data.
	// The kernel returns a DCAP v4 wrapper whose first 632 bytes are the
	// header || TDREPORT body. Use golang.org/x/sys/unix for the ioctl path.
	return nil, ErrNoHardware
}

// buildSyntheticQuote produces a TDX DCAP v4-shaped quote whose header version
// and tee_type are correct, whose mr_td matches the synthetic MRTD, and whose
// report_data first 32 bytes hold nonce. The trailing signature blob is the
// supplied bytes (or 64 zero bytes if none given).
func (a *TDXAttester) buildSyntheticQuote(nonce []byte) []byte {
	header := make([]byte, TDXHeaderSize)
	if a.synthetic.OverrideVersion != 0 {
		binary.LittleEndian.PutUint16(header[tdxVersionOffset:], a.synthetic.OverrideVersion)
	} else {
		binary.LittleEndian.PutUint16(header[tdxVersionOffset:], 4)
	}
	if a.synthetic.OmitTeeTypeMatch {
		binary.LittleEndian.PutUint32(header[tdxTeeTypeOffset:], 0xDEADBEEF)
	} else {
		binary.LittleEndian.PutUint32(header[tdxTeeTypeOffset:], TDXTeeTypeTDX)
	}

	body := make([]byte, TDXBodySize)
	copy(body[tdxMRTDOffset:tdxMRTDOffset+TDXMRTDSize], a.synthetic.MRTD[:])
	copy(body[tdxReportDataOffset:tdxReportDataOffset+NonceSize], nonce)

	sig := a.synthetic.SignatureBlob
	if len(sig) < tdxMinSignatureBlobSize {
		sig = make([]byte, tdxMinSignatureBlobSize)
	}

	out := make([]byte, 0, TDXSignedSize+len(sig))
	out = append(out, header...)
	out = append(out, body...)
	out = append(out, sig...)
	return out
}
