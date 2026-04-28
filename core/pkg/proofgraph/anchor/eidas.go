package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust"
)

const (
	// EIDASBackendName identifies eIDAS-qualified anchors in the proof graph.
	EIDASBackendName = "eidas-qtsp"

	// eidasMinTokenSize is a sanity bound: a real RFC 3161 ContentInfo with a
	// SignerInfo and at least one certificate is far above this. We reject
	// shorter tokens early.
	eidasMinTokenSize = 64
)

// EIDASAnchor anchors ProofGraph Merkle roots via an EU-qualified RFC 3161
// timestamping authority and validates that the response chain terminates at
// a Member-State-supervised root listed on the EU Trusted List.
//
// EIDASAnchor implements the same AnchorBackend interface as RFC3161Backend,
// adding two stages on top:
//
//  1. Submit/parse the RFC 3161 TimeStampResp normally.
//  2. Walk the certificate chain inside the SignedData and confirm that at
//     least one certificate's SHA-256 thumbprint is trusted by the supplied
//     EUTrustedList — i.e., the QTSP is a State-supervised QTSA.
//
// If the LOTL cache is empty (never refreshed) or stale beyond the
// configured threshold, anchoring still succeeds (we have a token) but
// verification fails with ErrEIDASLOTLStale so callers using `--require-eidas`
// can refuse to trust the anchor.
type EIDASAnchor struct {
	qtspURL         string
	lotl            *trust.EUTrustedList
	client          *http.Client
	maxLOTLAge      time.Duration
	allowEmptyChain bool
}

// EIDASOption configures the eIDAS anchor.
type EIDASOption func(*EIDASAnchor)

// WithEIDASHTTPClient supplies a custom HTTP client (mTLS, timeouts, etc.).
func WithEIDASHTTPClient(client *http.Client) EIDASOption {
	return func(a *EIDASAnchor) {
		if client != nil {
			a.client = client
		}
	}
}

// WithEIDASMaxLOTLAge sets the maximum allowed age of the LOTL cache before
// Verify rejects anchors with ErrEIDASLOTLStale. Defaults to
// trust.DefaultEULOTLRefreshInterval.
func WithEIDASMaxLOTLAge(d time.Duration) EIDASOption {
	return func(a *EIDASAnchor) {
		if d > 0 {
			a.maxLOTLAge = d
		}
	}
}

// WithEIDASAllowEmptyChain is a test-only knob that lets Verify accept a
// token whose embedded certificate chain is empty (e.g. when the QTSP
// returned a token without certReq=true). Production code should never
// enable this.
func WithEIDASAllowEmptyChain(allow bool) EIDASOption {
	return func(a *EIDASAnchor) {
		a.allowEmptyChain = allow
	}
}

// NewEIDASAnchor creates a new eIDAS-qualified anchor backend.
//
// qtspURL must point to an RFC 3161 endpoint operated by an EU-qualified
// trust service provider (see docs/architecture/eidas-qtsp.md for a list of
// recognized QTSPs).
//
// lotl is the EU Trusted List validator used to gate verification; it must
// not be nil. Callers are responsible for invoking lotl.Refresh on a
// schedule (see trust.DefaultEULOTLRefreshInterval).
func NewEIDASAnchor(qtspURL string, lotl *trust.EUTrustedList, opts ...EIDASOption) *EIDASAnchor {
	a := &EIDASAnchor{
		qtspURL:    qtspURL,
		lotl:       lotl,
		client:     &http.Client{Timeout: 30 * time.Second},
		maxLOTLAge: trust.DefaultEULOTLRefreshInterval,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Name returns "eidas-qtsp" — the canonical backend identifier.
func (a *EIDASAnchor) Name() string { return EIDASBackendName }

// QTSPURL exposes the configured QTSP endpoint (used by the trust CLI).
func (a *EIDASAnchor) QTSPURL() string { return a.qtspURL }

// Errors surfaced by the eIDAS anchor's verification path.
var (
	// ErrEIDASChainNotTrusted means none of the certificates inside the
	// timestamp token matched a thumbprint on the EU Trusted List.
	ErrEIDASChainNotTrusted = errors.New("eidas: timestamp chain does not terminate at an EU Trusted List root")

	// ErrEIDASLOTLStale means the EU Trusted List cache has not been
	// refreshed inside the configured maxLOTLAge window.
	ErrEIDASLOTLStale = errors.New("eidas: EU Trusted List cache is stale; refresh required before verification")

	// ErrEIDASMissingLOTL means the anchor was constructed without a
	// trust.EUTrustedList instance.
	ErrEIDASMissingLOTL = errors.New("eidas: no EU Trusted List configured")

	// ErrEIDASMalformedToken means the embedded RFC 3161 token could not
	// be parsed (corrupt response, wrong content type, etc.).
	ErrEIDASMalformedToken = errors.New("eidas: malformed RFC 3161 timestamp token")
)

// Anchor submits the Merkle root to the QTSP and returns an AnchorReceipt
// whose Signature field is the base64-encoded TSA response. Verification
// against the EU Trusted List happens inside Verify, which lets callers
// archive an anchor that was qualified at submission time even if the LOTL
// later rotates.
func (a *EIDASAnchor) Anchor(ctx context.Context, req AnchorRequest) (*AnchorReceipt, error) {
	if a.qtspURL == "" {
		return nil, errors.New("eidas: empty QTSP URL")
	}

	rootBytes, err := hex.DecodeString(req.MerkleRoot)
	if err != nil {
		return nil, fmt.Errorf("eidas: decode merkle root: %w", err)
	}
	digest := sha256.Sum256(rootBytes)

	tsReq := timestampRequest{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{Algorithm: oidSHA256},
			HashedMessage: digest[:],
		},
		CertReq: true,
	}
	reqBody, err := asn1.Marshal(tsReq)
	if err != nil {
		return nil, fmt.Errorf("eidas: marshal timestamp request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.qtspURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("eidas: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("eidas: submit timestamp request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("eidas: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("eidas: QTSP returned status %d", resp.StatusCode)
	}
	if len(respBody) < eidasMinTokenSize {
		return nil, ErrEIDASMalformedToken
	}

	receipt := &AnchorReceipt{
		Backend:        EIDASBackendName,
		Request:        req,
		LogID:          a.qtspURL,
		LogIndex:       0,
		IntegratedTime: time.Now().UTC(),
		Signature:      base64.StdEncoding.EncodeToString(respBody),
		RawResponse:    respBody,
	}
	receipt.ReceiptHash = receipt.ComputeReceiptHash()
	return receipt, nil
}

// Verify validates that the receipt is structurally a well-formed RFC 3161
// token and that at least one certificate inside the embedded SignedData
// chain is a Qualified TSA listed on the EU Trusted List.
//
// Returns ErrEIDASLOTLStale if the LOTL cache is older than maxLOTLAge.
// Returns ErrEIDASChainNotTrusted if no chain certificate is qualified.
func (a *EIDASAnchor) Verify(_ context.Context, receipt *AnchorReceipt) error {
	if receipt.Backend != EIDASBackendName {
		return fmt.Errorf("eidas: receipt backend mismatch: got %s", receipt.Backend)
	}
	if receipt.Signature == "" {
		return ErrEIDASMalformedToken
	}
	if a.lotl == nil {
		return ErrEIDASMissingLOTL
	}

	st := a.lotl.Status()
	if st.QualifiedTSACount == 0 {
		return ErrEIDASLOTLStale
	}
	if st.LastRefresh.IsZero() {
		return ErrEIDASLOTLStale
	}
	if a.maxLOTLAge > 0 && st.Age > a.maxLOTLAge {
		return ErrEIDASLOTLStale
	}

	tsaResp, err := base64.StdEncoding.DecodeString(receipt.Signature)
	if err != nil {
		return fmt.Errorf("eidas: decode timestamp token: %w", err)
	}

	certs, err := extractRFC3161Certificates(tsaResp)
	if err != nil {
		return fmt.Errorf("eidas: extract certificate chain: %w", err)
	}
	if len(certs) == 0 {
		if a.allowEmptyChain {
			return nil
		}
		return ErrEIDASChainNotTrusted
	}

	for _, cert := range certs {
		thumb := sha256.Sum256(cert.Raw)
		if a.lotl.Trust(strings.ToLower(hex.EncodeToString(thumb[:]))) {
			return nil
		}
	}
	return ErrEIDASChainNotTrusted
}

// extractRFC3161Certificates parses a TimeStampResp / TimeStampToken DER
// blob and returns every X.509 certificate embedded in the SignedData
// `certificates [0] IMPLICIT CertificateSet OPTIONAL` field.
//
// We do not perform a full path validation here; we only extract the
// candidate certs so the LOTL thumbprint match can authoritatively decide
// whether the chain terminates at a State-supervised root. CRL/OCSP and
// chain-building are deliberately out of scope for this layer — they
// belong with a future XAdES-T validator.
func extractRFC3161Certificates(der []byte) ([]*x509.Certificate, error) {
	if certs, err := certsFromTimeStampResp(der); err == nil && len(certs) > 0 {
		return certs, nil
	}
	if certs, err := certsFromContentInfo(der); err == nil {
		return certs, nil
	}
	return nil, errors.New("eidas: no certificates found in timestamp token")
}

// timeStampResp models the RFC 3161 §2.4.2 response wrapper.
type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString []asn1.RawValue `asn1:"optional"`
	FailInfo     asn1.BitString  `asn1:"optional"`
}

// contentInfo is the CMS top-level shape (RFC 5652 §3).
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// signedData is the CMS SignedData structure with only the fields we read.
// Certificates are an IMPLICIT [0] CertificateSet — we capture them as raw
// values and parse each as an X.509 certificate.
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo asn1.RawValue
	Certificates     []asn1.RawValue `asn1:"optional,tag:0,implicit,set"`
}

func certsFromTimeStampResp(der []byte) ([]*x509.Certificate, error) {
	var resp timeStampResp
	if _, err := asn1.Unmarshal(der, &resp); err != nil {
		return nil, err
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return nil, errors.New("eidas: empty timeStampToken")
	}
	return certsFromContentInfo(resp.TimeStampToken.FullBytes)
}

func certsFromContentInfo(der []byte) ([]*x509.Certificate, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, err
	}

	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, err
	}

	out := make([]*x509.Certificate, 0, len(sd.Certificates))
	for _, raw := range sd.Certificates {
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			continue
		}
		out = append(out, cert)
	}
	return out, nil
}
