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
		// The DER token lives base64-encoded in Signature; raw DER must never
		// enter RawResponse (json.RawMessage), or seal canonicalization fails.
		Signature: base64.StdEncoding.EncodeToString(respBody),
	}
	receipt.ReceiptHash = receipt.ComputeReceiptHash()

	return receipt, nil
}

// Verify binds the RFC 3161 timestamp token to the anchored root: the response
// must be granted, carry a TSTInfo, and its SHA-256 message imprint must equal
// the digest Anchor submitted for receipt.Request.MerkleRoot.
//
// It does not validate the TSA's CMS signature or certificate chain, so it
// shows which root a token names, not that a trusted TSA issued it.
func (r *RFC3161Backend) Verify(_ context.Context, receipt *AnchorReceipt) error {
	if receipt.Backend != rfc3161BackendName {
		return fmt.Errorf("rfc3161: receipt backend mismatch: got %s", receipt.Backend)
	}

	if receipt.Signature == "" {
		return fmt.Errorf("rfc3161: empty timestamp token")
	}

	tsaResp, err := base64.StdEncoding.DecodeString(receipt.Signature)
	if err != nil {
		return fmt.Errorf("rfc3161: decode timestamp token: %w", err)
	}
	imprint, err := rfc3161MessageImprint(tsaResp)
	if err != nil {
		return err
	}
	rootBytes, err := hex.DecodeString(receipt.Request.MerkleRoot)
	if err != nil {
		return fmt.Errorf("rfc3161: decode merkle root: %w", err)
	}
	want := sha256.Sum256(rootBytes)
	if !imprint.HashAlgorithm.Algorithm.Equal(oidSHA256) || !bytes.Equal(imprint.HashedMessage, want[:]) {
		return fmt.Errorf("rfc3161: timestamp token does not bind merkle root %s", receipt.Request.MerkleRoot)
	}
	return nil
}

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

// encapsulatedContentInfo is the CMS EncapsulatedContentInfo (RFC 5652 §5.2).
type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

// tstInfoImprint reads TSTInfo (RFC 3161 §2.4.2) up to its message imprint.
type tstInfoImprint struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
}

// rfc3161MessageImprint extracts the TSTInfo message imprint from a
// TimeStampResp, or from a bare TimeStampToken, and rejects any response
// whose status is not granted.
func rfc3161MessageImprint(der []byte) (messageImprint, error) {
	token := der
	var resp timeStampResp
	if rest, err := asn1.Unmarshal(der, &resp); err == nil && len(rest) == 0 {
		if resp.Status.Status != 0 && resp.Status.Status != 1 {
			return messageImprint{}, fmt.Errorf("rfc3161: timestamp response not granted (status %d)", resp.Status.Status)
		}
		if len(resp.TimeStampToken.FullBytes) == 0 {
			return messageImprint{}, fmt.Errorf("rfc3161: timestamp response carries no token")
		}
		token = resp.TimeStampToken.FullBytes
	}
	var ci contentInfo
	if rest, err := asn1.Unmarshal(token, &ci); err != nil || len(rest) != 0 || !ci.ContentType.Equal(oidSignedData) {
		return messageImprint{}, fmt.Errorf("rfc3161: timestamp token is not CMS SignedData")
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return messageImprint{}, fmt.Errorf("rfc3161: parse SignedData: %w", err)
	}
	var eci encapsulatedContentInfo
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.FullBytes, &eci); err != nil || !eci.EContentType.Equal(oidTSTInfo) {
		return messageImprint{}, fmt.Errorf("rfc3161: timestamp token does not carry a TSTInfo")
	}
	var info tstInfoImprint
	if _, err := asn1.Unmarshal(eci.EContent, &info); err != nil {
		return messageImprint{}, fmt.Errorf("rfc3161: parse TSTInfo: %w", err)
	}
	return info.MessageImprint, nil
}
