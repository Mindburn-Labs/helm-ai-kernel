package tee

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const coseAlgES384 int64 = -35
const coseSign1Tag uint64 = 18

type nitroAttestationDocument struct {
	ModuleID    string
	TimestampMS uint64
	Digest      string
	PCRs        map[uint][]byte
	Certificate []byte
	CABundle    [][]byte
	Nonce       []byte
	UserData    []byte
}

func verifyNitroCOSE(raw []byte, expectedNonce []byte, roots TrustRoots) (*VerifyResult, error) {
	if len(roots.AWSNitroRoots) == 0 {
		return nil, fmt.Errorf("%w: no AWS Nitro roots configured", ErrChainUntrusted)
	}
	protected, payload, signature, err := parseCOSESign1(raw)
	if err != nil {
		return nil, err
	}
	if err := verifyCOSEAlgorithm(protected); err != nil {
		return nil, err
	}
	doc, err := parseNitroCBORPayload(payload)
	if err != nil {
		return nil, err
	}
	if !bytesEqual(doc.Nonce, expectedNonce) {
		return nil, ErrNonceMismatch
	}
	if err := denyDebugZeroPCRs(doc.PCRs); err != nil {
		return nil, err
	}
	leaf, err := verifyNitroCertificateChain(doc, roots)
	if err != nil {
		return nil, err
	}
	if err := verifyCOSESignature(leaf, protected, payload, signature); err != nil {
		return nil, err
	}
	return &VerifyResult{
		Platform:       PlatformNitro,
		Measurement:    nitroCompositeMeasurement(doc.PCRs),
		Nonce:          cloneBytes(doc.Nonce),
		ChainTrustedTo: "aws-nitro",
		PCRs:           clonePCRs(doc.PCRs),
		IssuedAt:       int64(doc.TimestampMS),
	}, nil
}

func parseCOSESign1(raw []byte) (protected []byte, payload []byte, signature []byte, err error) {
	var decoded any
	if err := cbor.Unmarshal(raw, &decoded); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: nitro COSE_Sign1 decode: %v", ErrMalformedQuote, err)
	}
	if tag, ok := decoded.(cbor.Tag); ok {
		if tag.Number != coseSign1Tag {
			return nil, nil, nil, fmt.Errorf("%w: nitro COSE tag %d, expected Sign1 tag 18", ErrMalformedQuote, tag.Number)
		}
		decoded = tag.Content
	}
	arr, ok := decoded.([]any)
	if !ok {
		return nil, nil, nil, fmt.Errorf("%w: nitro COSE_Sign1 payload is not an array", ErrMalformedQuote)
	}
	if len(arr) != 4 {
		return nil, nil, nil, fmt.Errorf("%w: nitro COSE_Sign1 has %d elements", ErrMalformedQuote, len(arr))
	}
	protected, ok = arr[0].([]byte)
	if !ok || len(protected) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: nitro COSE protected header missing", ErrMalformedQuote)
	}
	payload, ok = arr[2].([]byte)
	if !ok || len(payload) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: nitro COSE payload missing", ErrMalformedQuote)
	}
	signature, ok = arr[3].([]byte)
	if !ok || len(signature) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: nitro COSE signature missing", ErrMalformedQuote)
	}
	return protected, payload, signature, nil
}

func verifyCOSEAlgorithm(protected []byte) error {
	var hdr map[any]any
	if err := cbor.Unmarshal(protected, &hdr); err != nil {
		return fmt.Errorf("%w: nitro COSE protected header decode: %v", ErrMalformedQuote, err)
	}
	algRaw, ok := hdr[int64(1)]
	if !ok {
		algRaw, ok = hdr[uint64(1)]
	}
	if !ok {
		return fmt.Errorf("%w: nitro COSE alg header missing", ErrMalformedQuote)
	}
	alg, ok := int64Value(algRaw)
	if !ok || alg != coseAlgES384 {
		return fmt.Errorf("%w: nitro COSE alg %v, expected ES384", ErrChainUntrusted, algRaw)
	}
	return nil
}

func parseNitroCBORPayload(payload []byte) (*nitroAttestationDocument, error) {
	var raw map[any]any
	if err := cbor.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("%w: nitro payload decode: %v", ErrMalformedQuote, err)
	}
	doc := &nitroAttestationDocument{PCRs: make(map[uint][]byte)}
	doc.ModuleID, _ = stringField(raw, "module_id")
	doc.Digest, _ = stringField(raw, "digest")
	ts, ok := uint64Field(raw, "timestamp")
	if !ok {
		return nil, fmt.Errorf("%w: nitro timestamp missing", ErrMalformedQuote)
	}
	doc.TimestampMS = ts
	cert, ok := bytesField(raw, "certificate")
	if !ok {
		return nil, fmt.Errorf("%w: nitro certificate missing", ErrMalformedQuote)
	}
	doc.Certificate = cert
	doc.CABundle = bytesArrayField(raw, "cabundle")
	if len(doc.CABundle) == 0 {
		return nil, fmt.Errorf("%w: nitro cabundle missing", ErrMalformedQuote)
	}
	if nonce, ok := bytesField(raw, "nonce"); ok {
		doc.Nonce = nonce
	}
	if userData, ok := bytesField(raw, "user_data"); ok {
		doc.UserData = userData
	}
	pcrRaw, ok := raw["pcrs"]
	if !ok {
		return nil, fmt.Errorf("%w: nitro PCR map missing", ErrMalformedQuote)
	}
	pcrMap, ok := pcrRaw.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: nitro PCR map malformed", ErrMalformedQuote)
	}
	for k, v := range pcrMap {
		idx, ok := uint64Value(k)
		if !ok {
			return nil, fmt.Errorf("%w: nitro PCR index malformed", ErrMalformedQuote)
		}
		pcr, ok := v.([]byte)
		if !ok || len(pcr) == 0 {
			return nil, fmt.Errorf("%w: nitro PCR %d malformed", ErrMalformedQuote, idx)
		}
		doc.PCRs[uint(idx)] = cloneBytes(pcr)
	}
	if doc.Digest != "" && doc.Digest != "SHA384" {
		return nil, fmt.Errorf("%w: nitro digest %q unsupported", ErrMalformedQuote, doc.Digest)
	}
	return doc, nil
}

func verifyNitroCertificateChain(doc *nitroAttestationDocument, roots TrustRoots) (*x509.Certificate, error) {
	leaf, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return nil, fmt.Errorf("%w: nitro leaf certificate parse: %v", ErrMalformedQuote, err)
	}
	rootPool := x509.NewCertPool()
	for _, der := range roots.AWSNitroRoots {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: AWS Nitro root parse: %v", ErrChainUntrusted, err)
		}
		rootPool.AddCert(cert)
	}
	intermediates := x509.NewCertPool()
	for _, der := range doc.CABundle {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: nitro cabundle parse: %v", ErrMalformedQuote, err)
		}
		if !cert.Equal(leaf) {
			intermediates.AddCert(cert)
		}
	}
	currentTime := time.UnixMilli(int64(doc.TimestampMS)).UTC()
	if currentTime.IsZero() {
		currentTime = time.Now().UTC()
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: intermediates, CurrentTime: currentTime}); err != nil {
		return nil, fmt.Errorf("%w: nitro certificate chain: %v", ErrChainUntrusted, err)
	}
	return leaf, nil
}

func verifyCOSESignature(leaf *x509.Certificate, protected []byte, payload []byte, signature []byte) error {
	toSign, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		return fmt.Errorf("%w: nitro COSE Sig_structure marshal: %v", ErrMalformedQuote, err)
	}
	sum := sha512.Sum384(toSign)
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: nitro leaf public key is not ECDSA", ErrChainUntrusted)
	}
	if len(signature) == 96 {
		r := new(big.Int).SetBytes(signature[:48])
		s := new(big.Int).SetBytes(signature[48:])
		if ecdsa.Verify(pub, sum[:], r, s) {
			return nil
		}
		return fmt.Errorf("%w: nitro COSE signature invalid", ErrChainUntrusted)
	}
	if ecdsa.VerifyASN1(pub, sum[:], signature) {
		return nil
	}
	return fmt.Errorf("%w: nitro COSE signature invalid", ErrChainUntrusted)
}

func denyDebugZeroPCRs(pcrs map[uint][]byte) error {
	for _, idx := range []uint{0, 1, 2, 3, 4, 8} {
		pcr, ok := pcrs[idx]
		if !ok {
			continue
		}
		if allZero(pcr) {
			return fmt.Errorf("%w: nitro PCR%d is zeroed debug-mode measurement", ErrChainUntrusted, idx)
		}
	}
	return nil
}

func nitroCompositeMeasurement(pcrs map[uint][]byte) []byte {
	out := make([]byte, 0, NitroPCRSize*6)
	for _, idx := range []uint{0, 1, 2, 3, 4, 8} {
		if pcr := pcrs[idx]; len(pcr) > 0 {
			out = append(out, pcr...)
		}
	}
	return out
}

func allZero(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func clonePCRs(in map[uint][]byte) map[uint][]byte {
	if len(in) == 0 {
		return nil
	}
	out := make(map[uint][]byte, len(in))
	for k, v := range in {
		out[k] = cloneBytes(v)
	}
	return out
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func stringField(m map[any]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func bytesField(m map[any]any, key string) ([]byte, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, false
	}
	return cloneBytes(b), true
}

func bytesArrayField(m map[any]any, key string) [][]byte {
	v, ok := m[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([][]byte, 0, len(arr))
	for _, item := range arr {
		if b, ok := item.([]byte); ok {
			out = append(out, cloneBytes(b))
		}
	}
	return out
}

func uint64Field(m map[any]any, key string) (uint64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	return uint64Value(v)
}

func uint64Value(v any) (uint64, bool) {
	switch n := v.(type) {
	case uint64:
		return n, true
	case uint32:
		return uint64(n), true
	case uint:
		return uint64(n), true
	case int:
		if n >= 0 {
			return uint64(n), true
		}
	case int64:
		if n >= 0 {
			return uint64(n), true
		}
	}
	return 0, false
}

func int64Value(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case uint64:
		return int64(n), true
	case uint:
		return int64(n), true
	}
	return 0, false
}
