package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

const rfc3161BackendName = "rfc3161"

// RFC3161Backend anchors ProofGraph Merkle roots via RFC 3161 timestamping authorities.
// This provides a standards-based fallback when Sigstore Rekor is unavailable.
type RFC3161Backend struct {
	tsaURL string
	client *http.Client
}

// RFC3161Option configures the RFC 3161 backend.
type RFC3161Option func(*RFC3161Backend)

// WithTSAURL sets the TSA endpoint URL.
func WithTSAURL(url string) RFC3161Option {
	return func(r *RFC3161Backend) {
		r.tsaURL = url
	}
}

// WithRFC3161HTTPClient sets a custom HTTP client.
func WithRFC3161HTTPClient(client *http.Client) RFC3161Option {
	return func(r *RFC3161Backend) {
		r.client = client
	}
}

// NewRFC3161Backend creates a new RFC 3161 timestamping backend.
func NewRFC3161Backend(tsaURL string, opts ...RFC3161Option) *RFC3161Backend {
	r := &RFC3161Backend{
		tsaURL: tsaURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Name returns "rfc3161".
func (r *RFC3161Backend) Name() string { return rfc3161BackendName }

// timestampRequest builds a minimal RFC 3161 TimeStampReq ASN.1 structure.
// See RFC 3161 Section 2.4.1.
type timestampRequest struct {
	Version        int
	MessageImprint messageImprint
	CertReq        bool `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type algorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

// SHA-256 OID: 2.16.840.1.101.3.4.2.1
var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

// Anchor submits the Merkle root hash to an RFC 3161 TSA.
func (r *RFC3161Backend) Anchor(ctx context.Context, req AnchorRequest) (*AnchorReceipt, error) {
	// Compute SHA-256 of the Merkle root for the timestamp request.
	rootBytes, err := hex.DecodeString(req.MerkleRoot)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: decode merkle root: %w", err)
	}
	digest := sha256.Sum256(rootBytes)

	// Build ASN.1 TimeStampReq
	tsReq := timestampRequest{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{
				Algorithm: oidSHA256,
			},
			HashedMessage: digest[:],
		},
		CertReq: true,
	}

	reqBody, err := asn1.Marshal(tsReq)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: marshal timestamp request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.tsaURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("rfc3161: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: submit request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rfc3161: unexpected status %d", resp.StatusCode)
	}

	// Store the raw TSA response as the receipt signature.
	receipt := &AnchorReceipt{
		Backend:        rfc3161BackendName,
		Request:        req,
		LogID:          r.tsaURL,
		LogIndex:       0, // RFC 3161 doesn't have log indices
		IntegratedTime: time.Now().UTC(),
		Signature:      base64.StdEncoding.EncodeToString(respBody),
		RawResponse:    respBody,
	}
	receipt.ReceiptHash = receipt.ComputeReceiptHash()

	return receipt, nil
}

// Verify checks the RFC 3161 timestamp token.
// Full verification requires parsing the ASN.1 TimeStampResp and validating
// the TSA's certificate chain. This is a structural check.
func (r *RFC3161Backend) Verify(_ context.Context, receipt *AnchorReceipt) error {
	if receipt.Backend != rfc3161BackendName {
		return fmt.Errorf("rfc3161: receipt backend mismatch: got %s", receipt.Backend)
	}

	if receipt.Signature == "" {
		return fmt.Errorf("rfc3161: empty timestamp token")
	}

	// Decode the base64-encoded TSA response to verify it's valid ASN.1.
	tsaResp, err := base64.StdEncoding.DecodeString(receipt.Signature)
	if err != nil {
		return fmt.Errorf("rfc3161: decode timestamp token: %w", err)
	}

	// Verify the response is valid ASN.1 (structural check).
	var raw asn1.RawValue
	_, err = asn1.Unmarshal(tsaResp, &raw)
	if err != nil {
		return fmt.Errorf("rfc3161: invalid ASN.1 timestamp response: %w", err)
	}

	return nil
}
