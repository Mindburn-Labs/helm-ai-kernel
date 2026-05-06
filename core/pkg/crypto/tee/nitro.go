package tee

import (
	"context"
	"encoding/binary"
	"fmt"
	"runtime"
)

// AWS Nitro Enclaves attestation document.
//
// The canonical AWS Nitro attestation document is a COSE_Sign1 structure
// (RFC 8152) wrapping a CBOR-encoded payload with the following required
// fields:
//
//	module_id     text    Identifies the enclave instance.
//	digest        text    Hash algorithm in use ("SHA384").
//	timestamp     uint    Milliseconds since epoch.
//	pcrs          map     uint → 48-byte SHA-384 digest (PCR0..PCR15).
//	certificate   bytes   Leaf certificate signed by AWS root.
//	cabundle      array   Issuer chain to AWS Nitro Attestation PKI root.
//	public_key    bytes   Optional: enclave attestation public key.
//	user_data     bytes   Optional: caller-supplied bytes (for HELM, the
//	                      receipt's pre-signature canonical form).
//	nonce         bytes   Optional: caller-supplied nonce (32 bytes for HELM).
//
// HELM does not currently bundle a CBOR/COSE library in core/pkg/crypto. To
// keep the package self-contained we ship a self-describing binary container
// here that captures the same fields, and document the COSE_Sign1 upgrade as
// a follow-up. The verifier dispatches on Platform=PlatformNitro and consumes
// this binary container; field semantics match the AWS Nitro spec.
//
// Wire format (little-endian where multi-byte integers appear):
//
//	magic       [4]byte = 'H','N','T','R'
//	version     uint8   = 1
//	pcr0_len    uint16
//	pcr0        [pcr0_len]byte (SHA-384 = 48)
//	pcr1_len    uint16
//	pcr1        [pcr1_len]byte
//	pcr2_len    uint16
//	pcr2        [pcr2_len]byte
//	nonce       [32]byte
//	user_data_len uint16
//	user_data   [user_data_len]byte
//	sig_len     uint16
//	signature   [sig_len]byte (COSE_Sign1 signature in production; arbitrary
//	                            bytes accepted by tests)
//
// References:
//   - AWS Nitro Enclaves SDK: https://github.com/aws/aws-nitro-enclaves-sdk-c
//   - NSM API (Rust): https://github.com/aws/aws-nitro-enclaves-nsm-api
//   - AWS attestation document spec:
//     https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html

const (
	// NitroDocHeader is the 4-byte magic that prefixes a HELM-encoded Nitro
	// attestation document.
	NitroDocHeader = "HNTR"

	// NitroPCRSize is the SHA-384 digest size used by Nitro PCRs.
	NitroPCRSize = 48

	// NitroPCRsCovered is the count of PCRs the kernel always reports
	// (PCR0=enclave image, PCR1=Linux kernel, PCR2=app loader).
	NitroPCRsCovered = 3
)

// NitroDocument is a structured view over a HELM-encoded Nitro attestation
// document. The fields map 1:1 to the canonical AWS Nitro CBOR payload.
type NitroDocument struct {
	Version   uint8
	PCRs      map[uint][]byte // uint → 48-byte digest
	Nonce     []byte          // 32 bytes
	UserData  []byte
	Signature []byte
}

// Measurement concatenates PCR0..PCR2 into a single composite measurement.
// HELM uses this as the canonical "TCB measurement" for cross-platform
// receipt indexing.
func (d *NitroDocument) Measurement() []byte {
	if d == nil {
		return nil
	}
	out := make([]byte, 0, NitroPCRSize*NitroPCRsCovered)
	for i := uint(0); i < NitroPCRsCovered; i++ {
		pcr := d.PCRs[i]
		if len(pcr) != NitroPCRSize {
			pcr = make([]byte, NitroPCRSize)
		}
		out = append(out, pcr...)
	}
	return out
}

// ParseNitroDocument parses the HELM-encoded Nitro attestation document.
func ParseNitroDocument(raw []byte) (*NitroDocument, error) {
	if len(raw) < 5 {
		return nil, fmt.Errorf("%w: nitro document too short (%d bytes)", ErrMalformedQuote, len(raw))
	}
	if string(raw[0:4]) != NitroDocHeader {
		return nil, fmt.Errorf("%w: nitro magic mismatch", ErrMalformedQuote)
	}
	d := &NitroDocument{Version: raw[4], PCRs: make(map[uint][]byte, NitroPCRsCovered)}
	if d.Version != 1 {
		return nil, fmt.Errorf("%w: nitro document version %d not supported", ErrMalformedQuote, d.Version)
	}
	off := 5
	for i := uint(0); i < NitroPCRsCovered; i++ {
		if off+2 > len(raw) {
			return nil, fmt.Errorf("%w: nitro pcr%d length truncated", ErrMalformedQuote, i)
		}
		l := int(binary.LittleEndian.Uint16(raw[off : off+2]))
		off += 2
		if off+l > len(raw) {
			return nil, fmt.Errorf("%w: nitro pcr%d body truncated", ErrMalformedQuote, i)
		}
		pcr := make([]byte, l)
		copy(pcr, raw[off:off+l])
		d.PCRs[i] = pcr
		off += l
	}
	if off+NonceSize > len(raw) {
		return nil, fmt.Errorf("%w: nitro nonce truncated", ErrMalformedQuote)
	}
	d.Nonce = make([]byte, NonceSize)
	copy(d.Nonce, raw[off:off+NonceSize])
	off += NonceSize
	if off+2 > len(raw) {
		return nil, fmt.Errorf("%w: nitro user_data length truncated", ErrMalformedQuote)
	}
	udl := int(binary.LittleEndian.Uint16(raw[off : off+2]))
	off += 2
	if off+udl > len(raw) {
		return nil, fmt.Errorf("%w: nitro user_data body truncated", ErrMalformedQuote)
	}
	d.UserData = make([]byte, udl)
	copy(d.UserData, raw[off:off+udl])
	off += udl
	if off+2 > len(raw) {
		return nil, fmt.Errorf("%w: nitro signature length truncated", ErrMalformedQuote)
	}
	sl := int(binary.LittleEndian.Uint16(raw[off : off+2]))
	off += 2
	if off+sl > len(raw) {
		return nil, fmt.Errorf("%w: nitro signature body truncated", ErrMalformedQuote)
	}
	d.Signature = make([]byte, sl)
	copy(d.Signature, raw[off:off+sl])
	return d, nil
}

// EncodeNitroDocument serializes a Nitro document to the HELM wire format.
// Used by tests and by the synthetic adapter.
func EncodeNitroDocument(d *NitroDocument) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("tee/nitro: nil document")
	}
	if len(d.Nonce) != NonceSize {
		return nil, fmt.Errorf("tee/nitro: nonce length %d, expected %d", len(d.Nonce), NonceSize)
	}
	buf := make([]byte, 0, 4+1+(2+NitroPCRSize)*NitroPCRsCovered+NonceSize+2+len(d.UserData)+2+len(d.Signature))
	buf = append(buf, NitroDocHeader...)
	buf = append(buf, byte(1))
	for i := uint(0); i < NitroPCRsCovered; i++ {
		pcr := d.PCRs[i]
		if pcr == nil {
			pcr = make([]byte, NitroPCRSize)
		}
		var l [2]byte
		binary.LittleEndian.PutUint16(l[:], uint16(len(pcr)))
		buf = append(buf, l[:]...)
		buf = append(buf, pcr...)
	}
	buf = append(buf, d.Nonce...)
	var udl [2]byte
	binary.LittleEndian.PutUint16(udl[:], uint16(len(d.UserData)))
	buf = append(buf, udl[:]...)
	buf = append(buf, d.UserData...)
	var sl [2]byte
	binary.LittleEndian.PutUint16(sl[:], uint16(len(d.Signature)))
	buf = append(buf, sl[:]...)
	buf = append(buf, d.Signature...)
	return buf, nil
}

// NitroAttester is the AWS Nitro Enclaves RemoteAttester implementation.
type NitroAttester struct {
	devicePath string
	synthetic  *SyntheticNitro
}

// SyntheticNitro holds the inputs to build a HELM-encoded Nitro document
// without hardware. Tests use this to exercise the parser and verifier.
type SyntheticNitro struct {
	PCR0      [NitroPCRSize]byte
	PCR1      [NitroPCRSize]byte
	PCR2      [NitroPCRSize]byte
	UserData  []byte
	Signature []byte
}

// NewNitroAttester returns a Nitro attester. On hosts without /dev/nsm the
// returned attester's Quote() will return ErrNoHardware.
func NewNitroAttester() *NitroAttester {
	return &NitroAttester{devicePath: "/dev/nsm"}
}

// NewSyntheticNitroAttester returns an attester that builds a
// HELM-encoded Nitro document from the supplied static fields. Test use only.
func NewSyntheticNitroAttester(s *SyntheticNitro) *NitroAttester {
	return &NitroAttester{synthetic: s, devicePath: "/dev/nsm"}
}

// Platform reports PlatformNitro.
func (a *NitroAttester) Platform() Platform { return PlatformNitro }

// Measurement returns the synthetic PCR0..PCR2 concatenation when configured,
// otherwise ErrNoHardware.
func (a *NitroAttester) Measurement() ([]byte, error) {
	if a.synthetic != nil {
		out := make([]byte, 0, NitroPCRSize*NitroPCRsCovered)
		out = append(out, a.synthetic.PCR0[:]...)
		out = append(out, a.synthetic.PCR1[:]...)
		out = append(out, a.synthetic.PCR2[:]...)
		return out, nil
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("%w: Nitro requires linux", ErrNoHardware)
	}
	// Follow-up: real NSM ioctl on AWS Nitro Enclave guest.
	return nil, ErrNoHardware
}

// Quote returns a HELM-encoded Nitro attestation document.
func (a *NitroAttester) Quote(_ context.Context, nonce []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("tee/nitro: nonce length %d, expected %d", len(nonce), NonceSize)
	}
	if a.synthetic != nil {
		doc := &NitroDocument{
			Version:   1,
			PCRs:      map[uint][]byte{0: a.synthetic.PCR0[:], 1: a.synthetic.PCR1[:], 2: a.synthetic.PCR2[:]},
			Nonce:     nonce,
			UserData:  a.synthetic.UserData,
			Signature: a.synthetic.Signature,
		}
		return EncodeNitroDocument(doc)
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("%w: Nitro requires linux", ErrNoHardware)
	}
	// Follow-up: real NSM ioctl on AWS Nitro Enclave guest.
	//
	// On a Nitro enclave the kernel exposes /dev/nsm. The
	// aws-nitro-enclaves-nsm-api crate (Rust) issues NSM_GET_ATTESTATION_DOC
	// with user_data, nonce, and public_key fields; the response is a
	// COSE_Sign1 wrapping a CBOR payload. To upgrade this skeleton:
	//   1. Add github.com/fxamacker/cbor/v2 (already an indirect dep).
	//   2. Replace EncodeNitroDocument/ParseNitroDocument with COSE_Sign1
	//      build/parse using github.com/veraison/go-cose.
	//   3. Verify the leaf certificate against the AWS Nitro PKI root
	//      embedded in core/pkg/trust/tee_roots.go.
	return nil, ErrNoHardware
}
