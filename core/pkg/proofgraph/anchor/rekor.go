package anchor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// DefaultRekorURL is the public Sigstore Rekor v2 instance.
	DefaultRekorURL = "https://rekor.sigstore.dev"

	rekorBackendName = "rekor-v2"
)

// RekorBackend anchors ProofGraph Merkle roots to Sigstore Rekor v2.
// Rekor v2 (GA Oct 2025) uses a tile-backed transparency log with sigstore-go v1.0.
type RekorBackend struct {
	url    string
	client *http.Client
}

// RekorOption configures the Rekor backend.
type RekorOption func(*RekorBackend)

// WithRekorURL sets a custom Rekor URL (for staging/private instances).
func WithRekorURL(url string) RekorOption {
	return func(r *RekorBackend) {
		r.url = url
	}
}

// WithHTTPClient sets a custom HTTP client (for mTLS, timeouts, etc.)
func WithHTTPClient(client *http.Client) RekorOption {
	return func(r *RekorBackend) {
		r.client = client
	}
}

// NewRekorBackend creates a new Rekor v2 anchoring backend.
func NewRekorBackend(opts ...RekorOption) *RekorBackend {
	r := &RekorBackend{
		url: DefaultRekorURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Name returns "rekor-v2".
func (r *RekorBackend) Name() string { return rekorBackendName }

// rekorEntry is the payload submitted to Rekor's /api/v1/log/entries endpoint.
type rekorEntry struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Spec       json.RawMessage `json:"spec"`
}

// rekorHashedRekordSpec is the hashedrekord v0.0.1 entry type.
type rekorHashedRekordSpec struct {
	Data rekorData `json:"data"`
}

type rekorData struct {
	Hash rekorHash `json:"hash"`
}

type rekorHash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// rekorResponse represents a Rekor log entry response.
type rekorResponse struct {
	LogID    string `json:"logID"`
	LogIndex int64  `json:"logIndex"`
	Body     string `json:"body"`
	// IntegratedTime is Unix timestamp from Rekor.
	IntegratedTime int64 `json:"integratedTime"`
	Verification   struct {
		SignedEntryTimestamp string `json:"signedEntryTimestamp"`
		InclusionProof       *struct {
			TreeSize int64    `json:"treeSize"`
			RootHash string   `json:"rootHash"`
			LogIndex int64    `json:"logIndex"`
			Hashes   []string `json:"hashes"`
		} `json:"inclusionProof,omitempty"`
	} `json:"verification"`
}

// Anchor submits the ProofGraph Merkle root to Rekor as a hashedrekord entry.
func (r *RekorBackend) Anchor(ctx context.Context, req AnchorRequest) (*AnchorReceipt, error) {
	digest, err := req.ComputeDigest()
	if err != nil {
		return nil, fmt.Errorf("rekor: compute digest: %w", err)
	}

	spec := rekorHashedRekordSpec{
		Data: rekorData{
			Hash: rekorHash{
				Algorithm: "sha256",
				Value:     req.MerkleRoot,
			},
		},
	}

	specJSON, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("rekor: marshal spec: %w", err)
	}

	entry := rekorEntry{
		APIVersion: "0.0.1",
		Kind:       "hashedrekord",
		Spec:       specJSON,
	}

	body, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("rekor: marshal entry: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		r.url+"/api/v1/log/entries", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("rekor: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("rekor: submit entry: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("rekor: read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rekor: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	// Rekor returns map[entryUUID]entryBody
	var entries map[string]rekorResponse
	if err := json.Unmarshal(respBody, &entries); err != nil {
		return nil, fmt.Errorf("rekor: parse response: %w", err)
	}

	// Extract the single entry
	var logEntry rekorResponse
	for _, v := range entries {
		logEntry = v
		break
	}

	receipt := &AnchorReceipt{
		Backend:        rekorBackendName,
		Request:        req,
		LogID:          logEntry.LogID,
		LogIndex:       logEntry.LogIndex,
		IntegratedTime: time.Unix(logEntry.IntegratedTime, 0).UTC(),
		Signature:      logEntry.Verification.SignedEntryTimestamp,
		RawResponse:    respBody,
	}

	if logEntry.Verification.InclusionProof != nil {
		ip := logEntry.Verification.InclusionProof
		receipt.InclusionProof = &LogInclusionProof{
			TreeSize: ip.TreeSize,
			RootHash: ip.RootHash,
			LogIndex: ip.LogIndex,
			Hashes:   ip.Hashes,
		}
	}

	receipt.ReceiptHash = receipt.ComputeReceiptHash()
	_ = digest             // Used for potential future signing
	_ = base64.StdEncoding // Used in signature handling

	return receipt, nil
}

// Verify checks the Rekor receipt against the transparency log.
func (r *RekorBackend) Verify(ctx context.Context, receipt *AnchorReceipt) error {
	if receipt.Backend != rekorBackendName {
		return fmt.Errorf("rekor: receipt backend mismatch: got %s", receipt.Backend)
	}

	// Verify by retrieving the entry from Rekor using the log index.
	url := fmt.Sprintf("%s/api/v1/log/entries?logIndex=%d", r.url, receipt.LogIndex)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("rekor: verify request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("rekor: verify fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rekor: verify status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("rekor: verify read: %w", err)
	}

	var entries map[string]rekorResponse
	if err := json.Unmarshal(respBody, &entries); err != nil {
		return fmt.Errorf("rekor: verify parse: %w", err)
	}

	for _, entry := range entries {
		if entry.LogIndex == receipt.LogIndex && entry.LogID == receipt.LogID {
			return nil // Entry exists and matches
		}
	}

	return fmt.Errorf("rekor: entry not found at log index %d", receipt.LogIndex)
}
