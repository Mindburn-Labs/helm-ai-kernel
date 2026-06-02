package tee

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/fxamacker/cbor/v2"
)

func TestMockAttesterAndVerifierCoverage(t *testing.T) {
	nonce := QuoteNonce([]byte("receipt-pre-signature-canonical-json"))
	att := NewDeterministicMockAttester([]byte("mock-seed"))
	if got := att.Platform(); got != PlatformMock {
		t.Fatalf("Platform() = %s, want %s", got, PlatformMock)
	}
	measurement, err := att.Measurement()
	if err != nil {
		t.Fatal(err)
	}
	measurement[0] ^= 0xff
	measurementAgain, err := att.Measurement()
	if err != nil {
		t.Fatal(err)
	}
	if measurementAgain[0] == measurement[0] {
		t.Fatal("Measurement returned an alias instead of a copy")
	}
	pub := att.PublicKey()
	pub[0] ^= 0xff
	if bytes.Equal(pub, att.PublicKey()) {
		t.Fatal("PublicKey returned an alias instead of a copy")
	}
	pub = att.PublicKey()
	raw, err := att.Quote(context.Background(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != MockQuoteSize {
		t.Fatalf("mock quote size = %d, want %d", len(raw), MockQuoteSize)
	}
	parsedMeasurement, parsedNonce, sig, err := ParseMockQuote(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsedMeasurement, measurementAgain) || !bytes.Equal(parsedNonce, nonce) || len(sig) != ed25519.SignatureSize {
		t.Fatalf("unexpected parsed mock quote fields: measurement=%x nonce=%x sig=%d", parsedMeasurement, parsedNonce, len(sig))
	}
	if err := VerifyMockQuote(raw, nonce, pub); err != nil {
		t.Fatalf("VerifyMockQuote rejected valid quote: %v", err)
	}
	roots := TrustRoots{AllowMock: true, MockPublicKeys: []ed25519.PublicKey{pub}}
	result, err := Verify(PlatformMock, raw, nonce, roots)
	if err != nil {
		t.Fatalf("Verify rejected valid mock quote: %v", err)
	}
	if result.ChainTrustedTo != "mock" || result.Platform != PlatformMock || !MeasurementMatches(result.Measurement, measurementAgain) {
		t.Fatalf("unexpected mock verify result: %+v", result)
	}
	if _, err := NewMockAttester(); err != nil {
		t.Fatalf("NewMockAttester failed: %v", err)
	}
}

func TestMockVerifierRejectsMalformedAndUntrustedQuotes(t *testing.T) {
	nonce := bytesOf(0x11, NonceSize)
	att := NewDeterministicMockAttester([]byte("mock-negative"))
	raw, err := att.Quote(context.Background(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	pub := att.PublicKey()
	cases := []struct {
		name string
		raw  []byte
	}{
		{name: "short", raw: raw[:len(raw)-1]},
		{name: "bad magic", raw: withByte(raw, 0, 'X')},
		{name: "bad version", raw: withByte(raw, 4, 9)},
	}
	for _, tc := range cases {
		if _, _, _, err := ParseMockQuote(tc.raw); !errors.Is(err, ErrMalformedQuote) {
			t.Fatalf("%s: expected malformed quote, got %v", tc.name, err)
		}
	}
	if _, err := att.Quote(context.Background(), []byte("short")); err == nil {
		t.Fatal("expected short nonce rejection")
	}
	if err := VerifyMockQuote(raw, []byte("short"), pub); err == nil || !strings.Contains(err.Error(), "expected nonce length") {
		t.Fatalf("expected expected-nonce length error, got %v", err)
	}
	if err := VerifyMockQuote(raw, bytesOf(0x22, NonceSize), pub); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("expected nonce mismatch, got %v", err)
	}
	if err := VerifyMockQuote(raw, nonce, ed25519.PublicKey([]byte("bad"))); err == nil || !strings.Contains(err.Error(), "ed25519 public key") {
		t.Fatalf("expected bad public key error, got %v", err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0xff
	if err := VerifyMockQuote(tampered, nonce, pub); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("expected chain error for tampered signature, got %v", err)
	}
	if _, err := Verify(PlatformMock, raw, nonce, TrustRoots{}); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("expected AllowMock=false rejection, got %v", err)
	}
	if _, err := Verify(PlatformMock, raw, nonce, TrustRoots{AllowMock: true}); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("expected missing mock keys rejection, got %v", err)
	}
	wrongPub := NewDeterministicMockAttester([]byte("other-key")).PublicKey()
	if _, err := Verify(PlatformMock, raw, nonce, TrustRoots{AllowMock: true, MockPublicKeys: []ed25519.PublicKey{wrongPub}}); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("expected wrong-key rejection, got %v", err)
	}
	if _, err := Verify(PlatformMock, raw, bytesOf(0x33, NonceSize), TrustRoots{AllowMock: true, MockPublicKeys: []ed25519.PublicKey{wrongPub}}); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("expected nonce mismatch to short-circuit wrong keys, got %v", err)
	}
	if _, err := Verify(Platform("mystery"), raw, nonce, TrustRoots{}); !errors.Is(err, ErrUnknownPlatform) {
		t.Fatalf("expected unknown platform error, got %v", err)
	}
	if _, err := Verify(PlatformMock, raw, []byte("short"), TrustRoots{AllowMock: true, MockPublicKeys: []ed25519.PublicKey{pub}}); err == nil || !strings.Contains(err.Error(), "expected nonce length") {
		t.Fatalf("expected verifier nonce length error, got %v", err)
	}
	if !bytesEqual([]byte{1, 2}, []byte{1, 2}) || bytesEqual([]byte{1}, []byte{1, 2}) || bytesEqual([]byte{1, 2}, []byte{1, 3}) {
		t.Fatal("bytesEqual returned an unexpected result")
	}
	if MeasurementMatches(nil, []byte{1}) || MeasurementMatches([]byte{1}, nil) || MeasurementMatches([]byte{1}, []byte{2}) {
		t.Fatal("MeasurementMatches accepted an invalid comparison")
	}
}

func TestSyntheticSEVSNPAttesterVerifierAndParserCoverage(t *testing.T) {
	nonce := bytesOf(0x44, NonceSize)
	synth := &SyntheticSEVSNP{
		Version:     2,
		Measurement: array48(0x51),
		ChipID:      array64(0x52),
		Signature:   array512(0x53),
	}
	att := NewSyntheticSEVSNPAttester(synth)
	if got := att.Platform(); got != PlatformSEVSNP {
		t.Fatalf("Platform() = %s", got)
	}
	measurement, err := att.Measurement()
	if err != nil {
		t.Fatal(err)
	}
	measurement[0] ^= 0xff
	measurementAgain, err := att.Measurement()
	if err != nil {
		t.Fatal(err)
	}
	if measurementAgain[0] == measurement[0] {
		t.Fatal("SEV-SNP Measurement returned an alias")
	}
	if _, err := att.Quote(context.Background(), []byte("short")); err == nil {
		t.Fatal("expected short nonce rejection")
	}
	raw, err := att.Quote(context.Background(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	report, err := ParseSEVSNPReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	if report.Version != 2 || !bytes.Equal(report.Nonce(), nonce) || !bytes.Equal(report.Measurement, measurementAgain) || len(report.Body) != SEVSNPBodySize {
		t.Fatalf("unexpected SEV-SNP report: %+v", report)
	}
	result, err := Verify(PlatformSEVSNP, raw, nonce, TrustRoots{})
	if err != nil {
		t.Fatalf("SEV-SNP relaxed verification failed: %v", err)
	}
	if result.ChainTrustedTo != "amd-kds-unverified" || len(result.Warnings) != 1 {
		t.Fatalf("unexpected relaxed SEV-SNP result: %+v", result)
	}
	if _, err := Verify(PlatformSEVSNP, raw, bytesOf(0x45, NonceSize), TrustRoots{}); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("expected nonce mismatch, got %v", err)
	}
	if _, err := Verify(PlatformSEVSNP, raw, nonce, TrustRoots{RequireSignedChain: true}); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("expected missing AMD roots rejection, got %v", err)
	}
	if _, err := Verify(PlatformSEVSNP, raw, nonce, TrustRoots{RequireSignedChain: true, AMDKDSRoots: [][]byte{{1}}}); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("expected pending strict SEV-SNP verifier rejection, got %v", err)
	}
	if _, err := ParseSEVSNPReport(raw[:len(raw)-1]); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected short report malformed error, got %v", err)
	}
	invalidVersion := append([]byte(nil), raw...)
	binary.LittleEndian.PutUint32(invalidVersion[sevsnpVersionOffset:], 1)
	if _, err := ParseSEVSNPReport(invalidVersion); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected invalid SEV-SNP version error, got %v", err)
	}
	if got := (*SEVSNPReport)(nil).Nonce(); got != nil {
		t.Fatalf("nil report nonce = %x", got)
	}
	if got := (&SEVSNPReport{ReportData: []byte{1, 2}}).Nonce(); got != nil {
		t.Fatalf("short report nonce = %x", got)
	}
	realAtt := NewSEVSNPAttester()
	if _, err := realAtt.Measurement(); !errors.Is(err, ErrNoHardware) {
		t.Fatalf("expected real SEV-SNP measurement hardware error, got %v", err)
	}
	if _, err := realAtt.Quote(context.Background(), nonce); !errors.Is(err, ErrNoHardware) {
		t.Fatalf("expected real SEV-SNP quote hardware error, got %v", err)
	}
}

func TestSyntheticTDXAttesterVerifierAndParserCoverage(t *testing.T) {
	nonce := bytesOf(0x61, NonceSize)
	synth := &SyntheticTDX{MRTD: array48(0x62), SignatureBlob: bytesOf(0x63, tdxMinSignatureBlobSize+4)}
	att := NewSyntheticTDXAttester(synth)
	if got := att.Platform(); got != PlatformTDX {
		t.Fatalf("Platform() = %s", got)
	}
	measurement, err := att.Measurement()
	if err != nil {
		t.Fatal(err)
	}
	measurement[0] ^= 0xff
	measurementAgain, err := att.Measurement()
	if err != nil {
		t.Fatal(err)
	}
	if measurementAgain[0] == measurement[0] {
		t.Fatal("TDX Measurement returned an alias")
	}
	if _, err := att.Quote(context.Background(), []byte("short")); err == nil {
		t.Fatal("expected short nonce rejection")
	}
	raw, err := att.Quote(context.Background(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	quote, err := ParseTDXQuote(raw)
	if err != nil {
		t.Fatal(err)
	}
	if quote.Version != 4 || quote.TeeType != TDXTeeTypeTDX || !bytes.Equal(quote.Nonce(), nonce) || !bytes.Equal(quote.MRTD, measurementAgain) || len(quote.Signature) != tdxMinSignatureBlobSize+4 {
		t.Fatalf("unexpected TDX quote: %+v", quote)
	}
	result, err := Verify(PlatformTDX, raw, nonce, TrustRoots{})
	if err != nil {
		t.Fatalf("TDX relaxed verification failed: %v", err)
	}
	if result.ChainTrustedTo != "intel-pcs-unverified" || len(result.Warnings) != 1 {
		t.Fatalf("unexpected relaxed TDX result: %+v", result)
	}
	if _, err := Verify(PlatformTDX, raw, bytesOf(0x64, NonceSize), TrustRoots{}); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("expected TDX nonce mismatch, got %v", err)
	}
	if _, err := Verify(PlatformTDX, raw, nonce, TrustRoots{RequireSignedChain: true}); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("expected missing Intel roots rejection, got %v", err)
	}
	if _, err := Verify(PlatformTDX, raw, nonce, TrustRoots{RequireSignedChain: true, IntelPCSRoots: [][]byte{{1}}}); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("expected pending strict TDX verifier rejection, got %v", err)
	}
	if _, err := ParseTDXQuote(raw[:TDXSignedSize+tdxMinSignatureBlobSize-1]); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected short TDX quote error, got %v", err)
	}
	badVersion, err := NewSyntheticTDXAttester(&SyntheticTDX{MRTD: array48(0x65), OverrideVersion: 3, SignatureBlob: bytesOf(0x66, tdxMinSignatureBlobSize)}).Quote(context.Background(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTDXQuote(badVersion); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected bad TDX version error, got %v", err)
	}
	badType, err := NewSyntheticTDXAttester(&SyntheticTDX{MRTD: array48(0x67), OmitTeeTypeMatch: true, SignatureBlob: bytesOf(0x68, tdxMinSignatureBlobSize)}).Quote(context.Background(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTDXQuote(badType); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected bad TDX tee type error, got %v", err)
	}
	defaultSig, err := NewSyntheticTDXAttester(&SyntheticTDX{MRTD: array48(0x69)}).Quote(context.Background(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	parsedDefaultSig, err := ParseTDXQuote(defaultSig)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedDefaultSig.Signature) != tdxMinSignatureBlobSize {
		t.Fatalf("default TDX signature size = %d", len(parsedDefaultSig.Signature))
	}
	if got := (*TDXQuote)(nil).Nonce(); got != nil {
		t.Fatalf("nil TDX quote nonce = %x", got)
	}
	if got := (&TDXQuote{ReportData: []byte{1, 2}}).Nonce(); got != nil {
		t.Fatalf("short TDX quote nonce = %x", got)
	}
	realAtt := NewTDXAttester()
	if _, err := realAtt.Measurement(); !errors.Is(err, ErrNoHardware) {
		t.Fatalf("expected real TDX measurement hardware error, got %v", err)
	}
	if _, err := realAtt.Quote(context.Background(), nonce); !errors.Is(err, ErrNoHardware) {
		t.Fatalf("expected real TDX quote hardware error, got %v", err)
	}
}

func TestNitroDocumentSyntheticAttesterAndParserCoverage(t *testing.T) {
	nonce := bytesOf(0x71, NonceSize)
	pcr0 := arrayNitroPCR(0x72)
	pcr1 := arrayNitroPCR(0x73)
	pcr2 := arrayNitroPCR(0x74)
	synth := &SyntheticNitro{PCR0: pcr0, PCR1: pcr1, PCR2: pcr2, UserData: []byte("user"), Signature: []byte("sig")}
	att := NewSyntheticNitroAttester(synth)
	if got := att.Platform(); got != PlatformNitro {
		t.Fatalf("Platform() = %s", got)
	}
	measurement, err := att.Measurement()
	if err != nil {
		t.Fatal(err)
	}
	measurement[0] ^= 0xff
	measurementAgain, err := att.Measurement()
	if err != nil {
		t.Fatal(err)
	}
	if measurementAgain[0] == measurement[0] {
		t.Fatal("Nitro Measurement returned an alias")
	}
	if _, err := att.Quote(context.Background(), []byte("short")); err == nil {
		t.Fatal("expected short nonce rejection")
	}
	raw, err := att.Quote(context.Background(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseNitroDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 || !bytes.Equal(doc.Nonce, nonce) || !bytes.Equal(doc.Measurement(), measurementAgain) || !bytes.Equal(doc.UserData, []byte("user")) || !bytes.Equal(doc.Signature, []byte("sig")) {
		t.Fatalf("unexpected Nitro document: %+v", doc)
	}
	result, err := Verify(PlatformNitro, raw, nonce, TrustRoots{})
	if err != nil {
		t.Fatalf("Nitro relaxed verification failed: %v", err)
	}
	if result.ChainTrustedTo != "aws-nitro-unverified" || len(result.Warnings) != 1 || len(result.PCRs) != NitroPCRsCovered {
		t.Fatalf("unexpected relaxed Nitro result: %+v", result)
	}
	if _, err := Verify(PlatformNitro, raw, bytesOf(0x75, NonceSize), TrustRoots{}); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("expected Nitro nonce mismatch, got %v", err)
	}
	if _, err := Verify(PlatformNitro, raw, nonce, TrustRoots{RequireSignedChain: true}); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("expected missing AWS roots rejection, got %v", err)
	}
	if _, err := Verify(PlatformNitro, raw, nonce, TrustRoots{RequireSignedChain: true, AWSNitroRoots: [][]byte{{1}}}); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected HELM binary document to fail COSE parser, got %v", err)
	}
	if got := (*NitroDocument)(nil).Measurement(); got != nil {
		t.Fatalf("nil document measurement = %x", got)
	}
	partialMeasurement := (&NitroDocument{PCRs: map[uint][]byte{0: pcr0[:]}}).Measurement()
	if len(partialMeasurement) != NitroPCRSize*NitroPCRsCovered || !bytes.Equal(partialMeasurement[NitroPCRSize:], make([]byte, NitroPCRSize*2)) {
		t.Fatalf("partial measurement did not zero-fill missing PCRs: %x", partialMeasurement)
	}
	if _, err := EncodeNitroDocument(nil); err == nil {
		t.Fatal("expected nil Nitro document rejection")
	}
	if _, err := EncodeNitroDocument(&NitroDocument{Nonce: []byte("short")}); err == nil {
		t.Fatal("expected bad nonce rejection")
	}
	realAtt := NewNitroAttester()
	if _, err := realAtt.Measurement(); !errors.Is(err, ErrNoHardware) {
		t.Fatalf("expected real Nitro measurement hardware error, got %v", err)
	}
	if _, err := realAtt.Quote(context.Background(), nonce); !errors.Is(err, ErrNoHardware) {
		t.Fatalf("expected real Nitro quote hardware error, got %v", err)
	}
}

func TestNitroDocumentParserRejectsMalformedInputs(t *testing.T) {
	nonce := bytesOf(0x81, NonceSize)
	doc := &NitroDocument{
		PCRs: map[uint][]byte{
			0: bytesOf(0x82, NitroPCRSize),
			1: bytesOf(0x83, NitroPCRSize),
			2: bytesOf(0x84, NitroPCRSize),
		},
		Nonce:     nonce,
		UserData:  []byte{1, 2, 3},
		Signature: []byte{4, 5, 6},
	}
	raw, err := EncodeNitroDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		raw  []byte
	}{
		{name: "too short", raw: []byte("HNTR")},
		{name: "bad magic", raw: withByte(raw, 0, 'X')},
		{name: "bad version", raw: withByte(raw, 4, 9)},
		{name: "pcr length truncated", raw: raw[:5]},
		{name: "pcr body truncated", raw: raw[:7]},
		{name: "nonce truncated", raw: raw[:5+(2+NitroPCRSize)*NitroPCRsCovered]},
		{name: "user data length truncated", raw: raw[:5+(2+NitroPCRSize)*NitroPCRsCovered+NonceSize]},
		{name: "user data body truncated", raw: raw[:5+(2+NitroPCRSize)*NitroPCRsCovered+NonceSize+2+1]},
		{name: "signature length truncated", raw: raw[:5+(2+NitroPCRSize)*NitroPCRsCovered+NonceSize+2+3]},
		{name: "signature body truncated", raw: raw[:5+(2+NitroPCRSize)*NitroPCRsCovered+NonceSize+2+3+2+1]},
	}
	for _, tc := range cases {
		if _, err := ParseNitroDocument(tc.raw); !errors.Is(err, ErrMalformedQuote) {
			t.Fatalf("%s: expected malformed Nitro document, got %v", tc.name, err)
		}
	}
}

func TestAttestationEnvelopeAndNitroPolicyCoverage(t *testing.T) {
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	result := &VerifyResult{Platform: PlatformNitro, Measurement: []byte{1, 2, 3}, Nonce: []byte{4, 5, 6}}
	profile := contracts.VerifierProfile{ProfileID: "profile-1", AppraisalPolicyHash: "sha256:policy"}
	env, err := NewAttestationResultEnvelope(AppraisalInput{
		Result:     result,
		Profile:    profile,
		EnvelopeID: "env-1",
		Subject:    "subject-1",
		Nonce:      "custom-nonce",
		PolicyHash: "sha256:override",
		Signature:  "sig",
		IssuedAt:   now,
		ExpiresAt:  now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if env.Nonce != "custom-nonce" || env.PolicyHash != "sha256:override" || env.MeasurementHash != "010203" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
	envelopeErrors := []struct {
		name string
		in   AppraisalInput
	}{
		{name: "nil result", in: AppraisalInput{Profile: profile, EnvelopeID: "env", Subject: "subject", Signature: "sig", ExpiresAt: now}},
		{name: "empty profile", in: AppraisalInput{Result: result, EnvelopeID: "env", Subject: "subject", Signature: "sig", ExpiresAt: now}},
		{name: "empty envelope", in: AppraisalInput{Result: result, Profile: profile, Subject: "subject", Signature: "sig", ExpiresAt: now}},
		{name: "empty subject", in: AppraisalInput{Result: result, Profile: profile, EnvelopeID: "env", Signature: "sig", ExpiresAt: now}},
		{name: "missing signature", in: AppraisalInput{Result: result, Profile: profile, EnvelopeID: "env", Subject: "subject", ExpiresAt: now}},
		{name: "missing expiry", in: AppraisalInput{Result: result, Profile: profile, EnvelopeID: "env", Subject: "subject", Signature: "sig"}},
	}
	for _, tc := range envelopeErrors {
		if _, err := NewAttestationResultEnvelope(tc.in); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}
	if idx, ok := parsePCRIndex("PCR0"); !ok || idx != 0 {
		t.Fatalf("parsePCRIndex(PCR0) = %d, %v", idx, ok)
	}
	if idx, ok := parsePCRIndex("8"); !ok || idx != 8 {
		t.Fatalf("parsePCRIndex(8) = %d, %v", idx, ok)
	}
	for _, name := range []string{"", "PCRx", "32"} {
		if _, ok := parsePCRIndex(name); ok {
			t.Fatalf("parsePCRIndex(%q) unexpectedly succeeded", name)
		}
	}
	pcr0 := bytesOf(0x91, NitroPCRSize)
	pcr1 := bytesOf(0x92, NitroPCRSize)
	actual := map[uint][]byte{0: pcr0, 1: pcr1}
	required := map[string]string{"PCR0": "sha384:" + hex.EncodeToString(pcr0), "1": "0x" + hex.EncodeToString(pcr1)}
	if err := validateNitroPCRPolicy(actual, required); err != nil {
		t.Fatalf("valid PCR policy rejected: %v", err)
	}
	if err := validateNitroPCRPolicy(actual, map[string]string{"PCRx": hex.EncodeToString(pcr0)}); err == nil {
		t.Fatal("expected invalid PCR key rejection")
	}
	if err := validateNitroPCRPolicy(actual, map[string]string{"PCR8": hex.EncodeToString(pcr0)}); err == nil {
		t.Fatal("expected missing PCR rejection")
	}
	if err := validateNitroPCRPolicy(actual, map[string]string{"PCR0": hex.EncodeToString(bytesOf(0x93, NitroPCRSize))}); err == nil {
		t.Fatal("expected PCR mismatch rejection")
	}
}

func TestNitroAppraiserEarlyValidationAndSignerFailure(t *testing.T) {
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	rootDER, leafDER, leafKey := nitroTestCerts(t, now)
	nonce := bytesOf(0xa1, NonceSize)
	pcr0 := bytesOf(0xa2, NitroPCRSize)
	raw := nitroCOSEFixture(t, leafDER, rootDER, leafKey, nonce, map[uint][]byte{
		0: pcr0,
		1: bytesOf(0xa3, NitroPCRSize),
		2: bytesOf(0xa4, NitroPCRSize),
		3: bytesOf(0xa5, NitroPCRSize),
		4: bytesOf(0xa6, NitroPCRSize),
		8: bytesOf(0xa7, NitroPCRSize),
	}, now, true)
	profile := contracts.VerifierProfile{
		ProfileID:           "nitro-prod",
		Platform:            "aws-nitro",
		AppraisalPolicyHash: "sha256:appraisal",
		RequiredPCRs:        map[string]string{"PCR0": hex.EncodeToString(pcr0)},
		ExpiresAt:           now.Add(time.Hour),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	appraiser := NitroAppraiser{Signer: staticEnvelopeSigner{}, Clock: func() time.Time { return now }}
	if _, err := appraiser.Appraise(ctx, raw, nonce, profile); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled context error, got %v", err)
	}
	if _, err := (NitroAppraiser{}).Appraise(context.Background(), raw, nonce, profile); err == nil {
		t.Fatal("expected missing signer rejection")
	}
	emptyProfile := profile
	emptyProfile.ProfileID = ""
	if _, err := appraiser.Appraise(context.Background(), raw, nonce, emptyProfile); err == nil {
		t.Fatal("expected empty profile rejection")
	}
	wrongPlatform := profile
	wrongPlatform.Platform = string(PlatformTDX)
	if _, err := appraiser.Appraise(context.Background(), raw, nonce, wrongPlatform); err == nil {
		t.Fatal("expected wrong platform rejection")
	}
	signingAppraiser := NitroAppraiser{
		Roots:   TrustRoots{AWSNitroRoots: [][]byte{rootDER}},
		Signer:  errorEnvelopeSigner{},
		Subject: "custom-subject",
		Clock:   func() time.Time { return now },
		TTL:     2 * time.Minute,
	}
	if _, err := signingAppraiser.Appraise(context.Background(), raw, nonce, profile); err == nil || !strings.Contains(err.Error(), "sign failed") {
		t.Fatalf("expected signer failure, got %v", err)
	}
}

func TestNitroCOSEDecoderHelperCoverage(t *testing.T) {
	badCBOR := []byte{0xff}
	if _, _, _, err := parseCOSESign1(badCBOR); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected malformed COSE decode, got %v", err)
	}
	if _, _, _, err := parseCOSESign1(mustCBOR(t, cbor.Tag{Number: 99, Content: []any{}})); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected wrong COSE tag error, got %v", err)
	}
	if _, _, _, err := parseCOSESign1(mustCBOR(t, map[string]string{"not": "array"})); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected non-array COSE error, got %v", err)
	}
	if _, _, _, err := parseCOSESign1(mustCBOR(t, []any{[]byte{1}})); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected wrong array length COSE error, got %v", err)
	}
	if _, _, _, err := parseCOSESign1(mustCBOR(t, []any{[]byte{}, map[int]any{}, []byte{1}, []byte{2}})); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected protected header error, got %v", err)
	}
	if _, _, _, err := parseCOSESign1(mustCBOR(t, []any{mustCBOR(t, map[int]int{1: int(coseAlgES384)}), map[int]any{}, []byte{}, []byte{2}})); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected payload missing error, got %v", err)
	}
	if _, _, _, err := parseCOSESign1(mustCBOR(t, []any{mustCBOR(t, map[int]int{1: int(coseAlgES384)}), map[int]any{}, []byte{1}, []byte{}})); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected signature missing error, got %v", err)
	}
	if err := verifyCOSEAlgorithm(badCBOR); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected algorithm decode error, got %v", err)
	}
	if err := verifyCOSEAlgorithm(mustCBOR(t, map[int]int{})); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected missing algorithm error, got %v", err)
	}
	if err := verifyCOSEAlgorithm(mustCBOR(t, map[uint64]int{1: -7})); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("expected unsupported algorithm error, got %v", err)
	}
	if err := verifyCOSEAlgorithm(mustCBOR(t, map[uint64]int{1: int(coseAlgES384)})); err != nil {
		t.Fatalf("expected uint alg header success, got %v", err)
	}
}

func TestNitroPayloadCertificateAndPrimitiveHelpers(t *testing.T) {
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	rootDER, leafDER, leafKey := nitroTestCerts(t, now)
	nonce := bytesOf(0xb1, NonceSize)
	pcrs := map[uint][]byte{0: bytesOf(0xb2, NitroPCRSize)}
	validPayload := map[string]any{
		"module_id":   "nitro-test",
		"digest":      "SHA384",
		"timestamp":   uint64(now.UnixMilli()),
		"pcrs":        pcrs,
		"certificate": leafDER,
		"cabundle":    [][]byte{rootDER},
		"nonce":       nonce,
		"user_data":   []byte("userdata"),
	}
	doc, err := parseNitroCBORPayload(mustCBOR(t, validPayload))
	if err != nil {
		t.Fatalf("valid Nitro payload rejected: %v", err)
	}
	if doc.ModuleID != "nitro-test" || doc.Digest != "SHA384" || !bytes.Equal(doc.Nonce, nonce) || !bytes.Equal(doc.UserData, []byte("userdata")) || len(doc.PCRs) != 1 {
		t.Fatalf("unexpected Nitro payload doc: %+v", doc)
	}
	payloadErrors := []struct {
		name    string
		payload any
	}{
		{name: "bad cbor", payload: nil},
		{name: "missing timestamp", payload: withoutKey(validPayload, "timestamp")},
		{name: "missing certificate", payload: withoutKey(validPayload, "certificate")},
		{name: "missing cabundle", payload: withoutKey(validPayload, "cabundle")},
		{name: "missing pcrs", payload: withoutKey(validPayload, "pcrs")},
		{name: "malformed pcr map", payload: withKey(validPayload, "pcrs", "bad")},
		{name: "malformed pcr index", payload: withKey(validPayload, "pcrs", map[any]any{"bad": []byte{1}})},
		{name: "malformed pcr value", payload: withKey(validPayload, "pcrs", map[uint][]byte{1: nil})},
		{name: "unsupported digest", payload: withKey(validPayload, "digest", "SHA256")},
	}
	for _, tc := range payloadErrors {
		var raw []byte
		if tc.payload == nil {
			raw = []byte{0xff}
		} else {
			raw = mustCBOR(t, tc.payload)
		}
		if _, err := parseNitroCBORPayload(raw); !errors.Is(err, ErrMalformedQuote) {
			t.Fatalf("%s: expected malformed payload, got %v", tc.name, err)
		}
	}
	if _, err := verifyNitroCertificateChain(&nitroAttestationDocument{Certificate: []byte("bad"), CABundle: [][]byte{rootDER}}, TrustRoots{AWSNitroRoots: [][]byte{rootDER}}); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected bad leaf certificate error, got %v", err)
	}
	if _, err := verifyNitroCertificateChain(&nitroAttestationDocument{Certificate: leafDER, CABundle: [][]byte{rootDER}}, TrustRoots{AWSNitroRoots: [][]byte{[]byte("bad")}}); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("expected bad root certificate error, got %v", err)
	}
	if _, err := verifyNitroCertificateChain(&nitroAttestationDocument{Certificate: leafDER, CABundle: [][]byte{[]byte("bad")}, TimestampMS: uint64(now.UnixMilli())}, TrustRoots{AWSNitroRoots: [][]byte{rootDER}}); !errors.Is(err, ErrMalformedQuote) {
		t.Fatalf("expected bad cabundle certificate error, got %v", err)
	}
	expiredDoc := &nitroAttestationDocument{Certificate: leafDER, CABundle: [][]byte{rootDER}, TimestampMS: uint64(now.Add(2 * time.Hour).UnixMilli())}
	if _, err := verifyNitroCertificateChain(expiredDoc, TrustRoots{AWSNitroRoots: [][]byte{rootDER}}); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("expected chain verification time error, got %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCOSESignature(leaf, mustCBOR(t, map[int]int{1: int(coseAlgES384)}), []byte("payload"), []byte("bad")); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("expected bad ECDSA signature error, got %v", err)
	}
	rsaCert := rsaLeafCertificate(t, now)
	if err := verifyCOSESignature(rsaCert, mustCBOR(t, map[int]int{1: int(coseAlgES384)}), []byte("payload"), []byte("bad")); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("expected non-ECDSA certificate error, got %v", err)
	}
	protected, err := cbor.Marshal(make(chan int))
	if err == nil {
		t.Fatalf("unexpected channel marshal success: %x", protected)
	}
	if clonePCRs(nil) != nil || cloneBytes(nil) != nil {
		t.Fatal("nil clone helpers should return nil")
	}
	originalPCRs := map[uint][]byte{0: []byte{1, 2}}
	clonedPCRs := clonePCRs(originalPCRs)
	clonedPCRs[0][0] = 9
	if originalPCRs[0][0] != 1 {
		t.Fatal("clonePCRs returned aliases")
	}
	if bytesArrayField(map[any]any{"cabundle": "bad"}, "cabundle") != nil || bytesArrayField(map[any]any{}, "cabundle") != nil {
		t.Fatal("bytesArrayField should reject missing/non-array values")
	}
	if got, ok := stringField(map[any]any{"s": 12}, "s"); ok || got != "" {
		t.Fatalf("stringField accepted non-string: %q %v", got, ok)
	}
	if got, ok := bytesField(map[any]any{"b": "bad"}, "b"); ok || got != nil {
		t.Fatalf("bytesField accepted non-bytes: %x %v", got, ok)
	}
	for _, value := range []any{uint64(1), uint32(2), uint(3), int(4), int64(5)} {
		if got, ok := uint64Value(value); !ok || got == 0 {
			t.Fatalf("uint64Value(%T) = %d, %v", value, got, ok)
		}
	}
	for _, value := range []any{int64(1), int(2), uint64(3), uint(4)} {
		if got, ok := int64Value(value); !ok || got == 0 {
			t.Fatalf("int64Value(%T) = %d, %v", value, got, ok)
		}
	}
	for _, value := range []any{int(-1), int64(-1), "bad"} {
		if got, ok := uint64Value(value); ok || got != 0 {
			t.Fatalf("uint64Value(%T) unexpectedly succeeded: %d", value, got)
		}
	}
	if got := nitroCompositeMeasurement(nil); len(got) != 0 {
		t.Fatalf("empty composite measurement = %x", got)
	}
	if allZero(nil) || !allZero([]byte{0, 0}) || allZero([]byte{0, 1}) {
		t.Fatal("allZero returned an unexpected result")
	}
	if leafKey == nil {
		t.Fatal("test certificate helper returned nil key")
	}
}

func TestSovereignKMSVaultAndProxyErrorCoverage(t *testing.T) {
	vault, err := NewSovereignKMSVault(PlatformMock, []byte("measurement-32-byte-stable-value"))
	if err != nil {
		t.Fatal(err)
	}
	badVault := &SovereignKMSVault{hardwareKey: []byte("short"), measurement: vault.measurement, platform: PlatformMock}
	if _, err := badVault.SealSecret(context.Background(), []byte("secret")); err == nil || !strings.Contains(err.Error(), "cipher initialization") {
		t.Fatalf("expected seal cipher initialization error, got %v", err)
	}
	sealed, err := vault.SealSecret(context.Background(), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := badVault.UnsealSecret(context.Background(), sealed); err == nil || !strings.Contains(err.Error(), "cipher initialization") {
		t.Fatalf("expected unseal cipher initialization error, got %v", err)
	}
	filter := NewSecretProxyFilter(vault)
	if err := filter.RegisterSecret(context.Background(), "good", sealed); err != nil {
		t.Fatal(err)
	}
	tampered := *sealed
	tampered.Ciphertext = append([]byte(nil), sealed.Ciphertext...)
	tampered.Ciphertext[0] ^= 0xff
	filter.sealedStore["good"] = &tampered
	if _, err := filter.InjectHeaders(context.Background(), map[string]string{"Authorization": "HELM_SECRET{good}"}); err == nil || !strings.Contains(err.Error(), "proxy decryption failed") {
		t.Fatalf("expected proxy decryption error, got %v", err)
	}
	otherVault, err := NewSovereignKMSVault(PlatformNitro, vault.measurement)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewSecretProxyFilter(otherVault).RegisterSecret(context.Background(), "bad", sealed); err == nil || !strings.Contains(err.Error(), "registry caching") {
		t.Fatalf("expected register secret unseal error, got %v", err)
	}
	filter.plainToToken[""] = "HELM_SECRET{empty}"
	if got := filter.FilterLogs("nothing to scrub"); got != "nothing to scrub" {
		t.Fatalf("empty secret scrub changed log: %q", got)
	}
}

type errorEnvelopeSigner struct{}

func (errorEnvelopeSigner) Sign([]byte) (string, error) {
	return "", errors.New("sign failed")
}

func array48(value byte) [48]byte {
	var out [48]byte
	for i := range out {
		out[i] = value
	}
	return out
}

func array64(value byte) [64]byte {
	var out [64]byte
	for i := range out {
		out[i] = value
	}
	return out
}

func array512(value byte) [512]byte {
	var out [512]byte
	for i := range out {
		out[i] = value
	}
	return out
}

func arrayNitroPCR(value byte) [NitroPCRSize]byte {
	var out [NitroPCRSize]byte
	for i := range out {
		out[i] = value
	}
	return out
}

func withByte(in []byte, idx int, value byte) []byte {
	out := append([]byte(nil), in...)
	out[idx] = value
	return out
}

func mustCBOR(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := cbor.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func withoutKey(in map[string]any, key string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if k != key {
			out[k] = v
		}
	}
	return out
}

func withKey(in map[string]any, key string, value any) map[string]any {
	out := withoutKey(in, "")
	out[key] = value
	return out
}

func rsaLeafCertificate(t *testing.T, now time.Time) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "RSA leaf"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
