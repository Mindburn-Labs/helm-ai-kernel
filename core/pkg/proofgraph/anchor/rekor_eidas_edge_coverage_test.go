package anchor

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

type anchorRoundTripFunc func(*http.Request) (*http.Response, error)

func (f anchorRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type failingReadCloser struct{}

func (failingReadCloser) Read(_ []byte) (int, error) {
	return 0, errors.New("read failed")
}

func (failingReadCloser) Close() error { return nil }

func TestRekorBackendHTTPErrorBranches(t *testing.T) {
	ctx := context.Background()
	req := AnchorRequest{MerkleRoot: hexRoot(), FromLamport: 1, ToLamport: 2, NodeCount: 1}

	badURL := NewRekorBackend(WithRekorURL("://bad"))
	if _, err := badURL.Anchor(ctx, req); err == nil {
		t.Fatal("Anchor invalid URL error = nil")
	}
	if err := badURL.Verify(ctx, &AnchorReceipt{Backend: rekorBackendName, LogIndex: 7}); err == nil {
		t.Fatal("Verify invalid URL error = nil")
	}

	doErrClient := &http.Client{Transport: anchorRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport down")
	})}
	doErr := NewRekorBackend(WithRekorURL("https://rekor.example"), WithHTTPClient(doErrClient))
	if _, err := doErr.Anchor(ctx, req); err == nil {
		t.Fatal("Anchor transport error = nil")
	}
	if err := doErr.Verify(ctx, &AnchorReceipt{Backend: rekorBackendName, LogIndex: 7}); err == nil {
		t.Fatal("Verify transport error = nil")
	}

	readErrClient := &http.Client{Transport: anchorRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		status := http.StatusOK
		if req.Method == http.MethodPost {
			status = http.StatusCreated
		}
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       failingReadCloser{},
			Request:    req,
		}, nil
	})}
	readErr := NewRekorBackend(WithRekorURL("https://rekor.example"), WithHTTPClient(readErrClient))
	if _, err := readErr.Anchor(ctx, req); err == nil {
		t.Fatal("Anchor read error = nil")
	}
	if err := readErr.Verify(ctx, &AnchorReceipt{Backend: rekorBackendName, LogIndex: 7}); err == nil {
		t.Fatal("Verify read error = nil")
	}

	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer statusServer.Close()
	statusBackend := NewRekorBackend(WithRekorURL(statusServer.URL), WithHTTPClient(statusServer.Client()))
	if _, err := statusBackend.Anchor(ctx, req); err == nil {
		t.Fatal("Anchor non-2xx status error = nil")
	}
	if err := statusBackend.Verify(ctx, &AnchorReceipt{Backend: rekorBackendName, LogIndex: 7}); err == nil {
		t.Fatal("Verify non-200 status error = nil")
	}

	parseServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
		}
		_, _ = w.Write([]byte("{"))
	}))
	defer parseServer.Close()
	parseBackend := NewRekorBackend(WithRekorURL(parseServer.URL), WithHTTPClient(parseServer.Client()))
	if _, err := parseBackend.Anchor(ctx, req); err == nil {
		t.Fatal("Anchor JSON parse error = nil")
	}
	if err := parseBackend.Verify(ctx, &AnchorReceipt{Backend: rekorBackendName, LogIndex: 7}); err == nil {
		t.Fatal("Verify JSON parse error = nil")
	}

	notFoundServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := map[string]rekorResponse{
			"other": {LogID: "other-log", LogIndex: 999},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer notFoundServer.Close()
	notFound := NewRekorBackend(WithRekorURL(notFoundServer.URL), WithHTTPClient(notFoundServer.Client()))
	if err := notFound.Verify(ctx, &AnchorReceipt{Backend: rekorBackendName, LogID: "wanted", LogIndex: 7}); err == nil {
		t.Fatal("Verify missing entry error = nil")
	}

	if err := notFound.Verify(ctx, &AnchorReceipt{Backend: "other", LogIndex: 7}); err == nil {
		t.Fatal("Verify backend mismatch error = nil")
	}
}

func TestEIDASAnchorTransportAndVerifyErrorBranches(t *testing.T) {
	ctx := context.Background()
	req := AnchorRequest{MerkleRoot: hexRoot(), FromLamport: 1, ToLamport: 2, NodeCount: 1}

	badURL := NewEIDASAnchor("://bad", trust.NewEUTrustedList())
	if _, err := badURL.Anchor(ctx, req); err == nil {
		t.Fatal("Anchor invalid URL error = nil")
	}

	doErrClient := &http.Client{Transport: anchorRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("qtsp down")
	})}
	doErr := NewEIDASAnchor("https://qtsp.example/tsa", trust.NewEUTrustedList(), WithEIDASHTTPClient(doErrClient))
	if _, err := doErr.Anchor(ctx, req); err == nil {
		t.Fatal("Anchor transport error = nil")
	}

	readErrClient := &http.Client{Transport: anchorRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       failingReadCloser{},
			Request:    req,
		}, nil
	})}
	readErr := NewEIDASAnchor("https://qtsp.example/tsa", trust.NewEUTrustedList(), WithEIDASHTTPClient(readErrClient))
	if _, err := readErr.Anchor(ctx, req); err == nil {
		t.Fatal("Anchor read error = nil")
	}

	a := NewEIDASAnchor("https://qtsp.example/tsa", loadedAnchorLOTL(t, strings.Repeat("a", 64)))
	if err := a.Verify(ctx, &AnchorReceipt{Backend: EIDASBackendName, Signature: "not-base64"}); err == nil {
		t.Fatal("Verify invalid base64 error = nil")
	}
	badDER := base64.StdEncoding.EncodeToString([]byte("not-der"))
	if err := a.Verify(ctx, &AnchorReceipt{Backend: EIDASBackendName, Signature: badDER}); err == nil {
		t.Fatal("Verify malformed token error = nil")
	}
}

func TestEIDASCertificateExtractionEdgeBranches(t *testing.T) {
	cert := generateSyntheticTSACert(t, "Wrapped TimeStampResp")
	token := buildSyntheticToken(t, []*x509.Certificate{cert})
	wrapped, err := asn1.Marshal(timeStampResp{
		Status:         pkiStatusInfo{Status: 0},
		TimeStampToken: asn1.RawValue{FullBytes: token},
	})
	if err != nil {
		t.Fatalf("marshal TimeStampResp: %v", err)
	}
	certs, err := extractRFC3161Certificates(wrapped)
	if err != nil {
		t.Fatalf("extract wrapped certificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("wrapped cert count = %d, want 1", len(certs))
	}

	emptyToken, err := asn1.Marshal(timeStampResp{Status: pkiStatusInfo{Status: 0}})
	if err != nil {
		t.Fatalf("marshal empty TimeStampResp: %v", err)
	}
	if _, err := certsFromTimeStampResp(emptyToken); err == nil {
		t.Fatal("empty TimeStampResp token error = nil")
	}
	if _, err := certsFromContentInfo([]byte("not-der")); err == nil {
		t.Fatal("ContentInfo DER error = nil")
	}

	malformedSignedData := buildContentInfoDER(t, []byte("not-signed-data"))
	if _, err := certsFromContentInfo(malformedSignedData); err == nil {
		t.Fatal("SignedData DER error = nil")
	}

	invalidCertToken := buildSyntheticRawCertToken(t, []asn1.RawValue{{FullBytes: []byte{0x05, 0x00}}})
	certs, err = certsFromContentInfo(invalidCertToken)
	if err != nil {
		t.Fatalf("certsFromContentInfo invalid cert: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("invalid cert count = %d, want 0", len(certs))
	}

	if _, err := extractRFC3161Certificates([]byte{0x05, 0x00}); err == nil {
		t.Fatal("extract certificates not found error = nil")
	}
}

func TestServiceAnchorNowStoreError(t *testing.T) {
	svc, err := NewService(ServiceConfig{
		Backends: []AnchorBackend{&mockAnchorBackend{name: "ok"}},
		Store:    failingAnchorStore{},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, err := svc.AnchorNow(context.Background(), AnchorRequest{MerkleRoot: "root", ToLamport: 9}); err == nil {
		t.Fatal("AnchorNow store error = nil")
	}
	if svc.LastAnchoredLamport() != 0 {
		t.Fatalf("LastAnchoredLamport = %d, want 0 after store failure", svc.LastAnchoredLamport())
	}
}

type failingAnchorStore struct{}

func (failingAnchorStore) StoreReceipt(context.Context, *AnchorReceipt) error {
	return errors.New("store failed")
}

func (failingAnchorStore) GetLatestReceipt(context.Context) (*AnchorReceipt, error) {
	return nil, errors.New("store failed")
}

func (failingAnchorStore) GetReceiptByLamportRange(context.Context, uint64, uint64) ([]*AnchorReceipt, error) {
	return nil, errors.New("store failed")
}

func loadedAnchorLOTL(t *testing.T, thumbprints ...string) *trust.EUTrustedList {
	t.Helper()
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	lotl := trust.NewEUTrustedListWithConfig(trust.EUTrustedListConfig{
		Now: func() time.Time { return now },
	})
	if err := lotl.LoadFromBytes(buildLOTLBytesFor(t, thumbprints)); err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	return lotl
}

func buildSyntheticRawCertToken(t *testing.T, rawCerts []asn1.RawValue) []byte {
	t.Helper()
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
	if err != nil {
		t.Fatalf("marshal SignedData: %v", err)
	}
	return buildContentInfoDER(t, sdDER)
}

func buildContentInfoDER(t *testing.T, signedDataDER []byte) []byte {
	t.Helper()
	ci := contentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataDER,
		},
	}
	der, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("marshal ContentInfo: %v", err)
	}
	return der
}

func trustedThumbprint(cert *x509.Certificate) string {
	thumb := sha256.Sum256(cert.Raw)
	return strings.ToLower(hex.EncodeToString(thumb[:]))
}
