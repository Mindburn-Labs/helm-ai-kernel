package witness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// HTTPTransport implements witness attestation over HTTP.
// This is the network transport layer that was previously missing.
type HTTPTransport struct {
	client *http.Client
}

// NewHTTPTransport creates an HTTP transport for witness communication.
func NewHTTPTransport(timeout time.Duration) *HTTPTransport {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &HTTPTransport{
		client: &http.Client{Timeout: timeout},
	}
}

// RequestAttestation sends a WitnessRequest to a witness node over HTTP.
func (t *HTTPTransport) RequestAttestation(ctx context.Context, endpoint string, req WitnessRequest) (*WitnessAttestation, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("witness/http: marshal error: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/api/v1/attest", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("witness/http: request error: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("witness/http: transport error: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("witness/http: status %d", httpResp.StatusCode)
	}

	var att WitnessAttestation
	if err := json.NewDecoder(httpResp.Body).Decode(&att); err != nil {
		return nil, fmt.Errorf("witness/http: decode error: %w", err)
	}

	return &att, nil
}

// HTTPWitnessHandler returns an http.HandlerFunc for a WitnessNode.
// This allows any WitnessNode to be served over HTTP.
func HTTPWitnessHandler(node *WitnessNode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req WitnessRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		att, err := node.Attest(r.Context(), req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(att)
	}
}

// CollectAttestationsHTTP uses HTTP transport to collect attestations.
func (c *WitnessClient) CollectAttestationsHTTP(ctx context.Context, req WitnessRequest) ([]WitnessAttestation, error) {
	transport := NewHTTPTransport(c.policy.TimeoutPerNode)
	type result struct {
		att *WitnessAttestation
		err error
	}

	results := make(chan result, len(c.nodes))
	ctx, cancel := context.WithTimeout(ctx, c.policy.TimeoutPerNode*time.Duration(len(c.nodes)))
	defer cancel()

	for _, node := range c.nodes {
		go func(endpoint string) {
			att, err := transport.RequestAttestation(ctx, endpoint, req)
			results <- result{att, err}
		}(node.Address)
	}

	var attestations []WitnessAttestation
	validCount := 0

	for i := 0; i < len(c.nodes); i++ {
		select {
		case <-ctx.Done():
			break
		case r := <-results:
			if r.err != nil {
				continue
			}
			attestations = append(attestations, *r.att)
			if r.att.Verdict == "VALID" {
				validCount++
			}
			if validCount >= c.policy.MinWitnesses {
				return attestations, nil
			}
		}
	}

	if validCount >= c.policy.MinWitnesses {
		return attestations, nil
	}

	return attestations, fmt.Errorf("witness: only %d/%d valid attestations (need %d)",
		validCount, len(c.nodes), c.policy.MinWitnesses)
}
