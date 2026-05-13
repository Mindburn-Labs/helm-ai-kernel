package anchor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateSyntheticTSACert produces an ECDSA P-256 self-signed certificate
// suitable for embedding inside a fake RFC 3161 SignedData.
func generateSyntheticTSACert(t *testing.T, subject string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// buildSyntheticToken assembles a CMS SignedData ContentInfo carrying the
// supplied certificates. Designed to be parseable by extractRFC3161Certificates;
// not a cryptographically valid signature.
func buildSyntheticToken(t *testing.T, certs []*x509.Certificate) []byte {
	t.Helper()

	rawCerts := make([]asn1.RawValue, 0, len(certs))
	for _, c := range certs {
		rawCerts = append(rawCerts, asn1.RawValue{FullBytes: c.Raw})
	}

	sd := signedData{
		Version: 3,
		DigestAlgorithms: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      []byte{},
		},
		EncapContentInfo: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      []byte{},
		},
		Certificates: rawCerts,
	}
	sdDER, err := asn1.Marshal(sd)
	require.NoError(t, err)

	ci := contentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, // signedData OID
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdDER,
		},
	}
	ciDER, err := asn1.Marshal(ci)
	require.NoError(t, err)
	return ciDER
}

// buildLOTLBytesFor produces a synthetic LOTL XML carrying the supplied
// certificate thumbprints as Granted QTSAs (one TSP per thumbprint).
func buildLOTLBytesFor(t *testing.T, thumbprints []string) []byte {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	sb.WriteString("<TrustServiceStatusList>\n")
	sb.WriteString(`  <SchemeInformation><SchemeOperatorName><Name xml:lang="en">EC test</Name></SchemeOperatorName>` + "\n")
	sb.WriteString(`    <PointersToOtherTSL><OtherTSLPointer><TSLLocation>https://example/test.xml</TSLLocation>` +
		`<AdditionalInformation><OtherInformation><SchemeTerritory>EE</SchemeTerritory>` +
		`</OtherInformation></AdditionalInformation></OtherTSLPointer></PointersToOtherTSL>` + "\n")
	sb.WriteString("  </SchemeInformation>\n")
	sb.WriteString("  <TrustServiceProviderList>\n")
	for i, tp := range thumbprints {
		sb.WriteString(fmt.Sprintf(`    <TrustServiceProvider><TSPInformation><SchemeTerritory>EE</SchemeTerritory>`+
			`<TSPName><Name xml:lang="en">Synthetic QTSP %d</Name></TSPName></TSPInformation>`, i))
		sb.WriteString(`<TSPServices><TSPService><ServiceInformation>`)
		sb.WriteString(`<ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST</ServiceTypeIdentifier>`)
		sb.WriteString(`<ServiceName><Name xml:lang="en">Synthetic Service</Name></ServiceName>`)
		sb.WriteString(`<ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>`)
		sb.WriteString(`<ServiceDigitalIdentity><DigitalId>`)
		sb.WriteString(fmt.Sprintf(`<X509SubjectName>CN=Synthetic QTSP %d</X509SubjectName>`, i))
		sb.WriteString(fmt.Sprintf(`<X509CertificateSHA256>%s</X509CertificateSHA256>`, tp))
		sb.WriteString(`</DigitalId></ServiceDigitalIdentity>`)
		sb.WriteString(`</ServiceInformation></TSPService></TSPServices></TrustServiceProvider>` + "\n")
	}
	sb.WriteString("  </TrustServiceProviderList>\n")
	sb.WriteString("</TrustServiceStatusList>\n")
	return []byte(sb.String())
}

func TestEIDASAnchor_Name(t *testing.T) {
	a := NewEIDASAnchor("https://qtsp.example/tsa", trust.NewEUTrustedList())
	assert.Equal(t, EIDASBackendName, a.Name())
	assert.Equal(t, "eidas-qtsp", a.Name())
	assert.Equal(t, "https://qtsp.example/tsa", a.QTSPURL())
}

func TestEIDASAnchor_VerifyTrustsListedCert(t *testing.T) {
	cert := generateSyntheticTSACert(t, "Test EU QTSA")
	thumb := sha256.Sum256(cert.Raw)
	thumbHex := hex.EncodeToString(thumb[:])

	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	lotl := trust.NewEUTrustedListWithConfig(trust.EUTrustedListConfig{
		Now: func() time.Time { return now },
	})
	require.NoError(t, lotl.LoadFromBytes(buildLOTLBytesFor(t, []string{thumbHex})))

	tokenDER := buildSyntheticToken(t, []*x509.Certificate{cert})
	receipt := &AnchorReceipt{
		Backend:        EIDASBackendName,
		LogID:          "https://qtsp.example/tsa",
		IntegratedTime: now,
		Signature:      base64.StdEncoding.EncodeToString(tokenDER),
		RawResponse:    tokenDER,
	}
	receipt.ReceiptHash = receipt.ComputeReceiptHash()

	a := NewEIDASAnchor("https://qtsp.example/tsa", lotl)
	require.NoError(t, a.Verify(context.Background(), receipt))
}

func TestEIDASAnchor_VerifyRejectsUnlistedCert(t *testing.T) {
	cert := generateSyntheticTSACert(t, "Untrusted QTSA")

	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	otherThumb := strings.Repeat("a", 64)
	lotl := trust.NewEUTrustedListWithConfig(trust.EUTrustedListConfig{
		Now: func() time.Time { return now },
	})
	require.NoError(t, lotl.LoadFromBytes(buildLOTLBytesFor(t, []string{otherThumb})))

	tokenDER := buildSyntheticToken(t, []*x509.Certificate{cert})
	receipt := &AnchorReceipt{
		Backend:   EIDASBackendName,
		Signature: base64.StdEncoding.EncodeToString(tokenDER),
	}

	a := NewEIDASAnchor("https://qtsp.example/tsa", lotl)
	err := a.Verify(context.Background(), receipt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEIDASChainNotTrusted)
}

func TestEIDASAnchor_VerifyRejectsStaleLOTL(t *testing.T) {
	cert := generateSyntheticTSACert(t, "Test EU QTSA")
	thumb := sha256.Sum256(cert.Raw)
	thumbHex := hex.EncodeToString(thumb[:])

	loadedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	verifyAt := time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC) // ~118d later
	clock := loadedAt
	lotl := trust.NewEUTrustedListWithConfig(trust.EUTrustedListConfig{
		Now: func() time.Time { return clock },
	})
	require.NoError(t, lotl.LoadFromBytes(buildLOTLBytesFor(t, []string{thumbHex})))

	// Advance the clock so the cache is well past 24h.
	clock = verifyAt

	tokenDER := buildSyntheticToken(t, []*x509.Certificate{cert})
	receipt := &AnchorReceipt{
		Backend:   EIDASBackendName,
		Signature: base64.StdEncoding.EncodeToString(tokenDER),
	}

	a := NewEIDASAnchor("https://qtsp.example/tsa", lotl,
		WithEIDASMaxLOTLAge(24*time.Hour),
	)
	err := a.Verify(context.Background(), receipt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEIDASLOTLStale)
}

func TestEIDASAnchor_VerifyRejectsEmptyLOTL(t *testing.T) {
	cert := generateSyntheticTSACert(t, "Test EU QTSA")
	tokenDER := buildSyntheticToken(t, []*x509.Certificate{cert})
	receipt := &AnchorReceipt{
		Backend:   EIDASBackendName,
		Signature: base64.StdEncoding.EncodeToString(tokenDER),
	}

	a := NewEIDASAnchor("https://qtsp.example/tsa", trust.NewEUTrustedList())
	err := a.Verify(context.Background(), receipt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEIDASLOTLStale)
}

func TestEIDASAnchor_VerifyRejectsMissingLOTL(t *testing.T) {
	cert := generateSyntheticTSACert(t, "Test EU QTSA")
	tokenDER := buildSyntheticToken(t, []*x509.Certificate{cert})
	receipt := &AnchorReceipt{
		Backend:   EIDASBackendName,
		Signature: base64.StdEncoding.EncodeToString(tokenDER),
	}

	a := NewEIDASAnchor("https://qtsp.example/tsa", nil)
	err := a.Verify(context.Background(), receipt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEIDASMissingLOTL)
}

func TestEIDASAnchor_VerifyRejectsBackendMismatch(t *testing.T) {
	a := NewEIDASAnchor("https://qtsp.example/tsa", trust.NewEUTrustedList())
	receipt := &AnchorReceipt{Backend: "rfc3161", Signature: strings.Repeat("A", 200)}
	err := a.Verify(context.Background(), receipt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backend mismatch")
}

func TestEIDASAnchor_VerifyRejectsEmptySignature(t *testing.T) {
	a := NewEIDASAnchor("https://qtsp.example/tsa", trust.NewEUTrustedList())
	receipt := &AnchorReceipt{Backend: EIDASBackendName}
	err := a.Verify(context.Background(), receipt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEIDASMalformedToken)
}

func TestEIDASAnchor_AnchorRejectsBadMerkleRoot(t *testing.T) {
	a := NewEIDASAnchor("https://qtsp.example/tsa", trust.NewEUTrustedList())
	_, err := a.Anchor(context.Background(), AnchorRequest{MerkleRoot: "not-hex"})
	require.Error(t, err)
}

func TestEIDASAnchor_AnchorRejectsEmptyURL(t *testing.T) {
	a := NewEIDASAnchor("", trust.NewEUTrustedList())
	_, err := a.Anchor(context.Background(), AnchorRequest{MerkleRoot: hex.EncodeToString([]byte("root"))})
	require.Error(t, err)
}

func TestEIDASAnchor_AllowEmptyChainTestKnob(t *testing.T) {
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	lotl := trust.NewEUTrustedListWithConfig(trust.EUTrustedListConfig{
		Now: func() time.Time { return now },
	})
	require.NoError(t, lotl.LoadFromBytes(buildLOTLBytesFor(t, []string{strings.Repeat("e", 64)})))

	tokenDER := buildSyntheticToken(t, nil)
	receipt := &AnchorReceipt{
		Backend:   EIDASBackendName,
		Signature: base64.StdEncoding.EncodeToString(tokenDER),
	}

	// Without the test knob, an empty chain is rejected.
	strict := NewEIDASAnchor("https://qtsp.example/tsa", lotl)
	require.Error(t, strict.Verify(context.Background(), receipt))

	// With the knob, an empty chain is accepted.
	relaxed := NewEIDASAnchor("https://qtsp.example/tsa", lotl, WithEIDASAllowEmptyChain(true))
	require.NoError(t, relaxed.Verify(context.Background(), receipt))
}
