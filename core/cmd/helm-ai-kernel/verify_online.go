package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

type onlineProofResponse struct {
	Verified            bool    `json:"verified"`
	EnvelopeID          string  `json:"envelope_id,omitempty"`
	SealedAt            string  `json:"sealed_at,omitempty"`
	SignatureValidCount int     `json:"signature_valid_count,omitempty"`
	SignatureTotalCount int     `json:"signature_total_count,omitempty"`
	AnchorIndex         *uint64 `json:"anchor_index,omitempty"`
	MerkleRoot          string  `json:"merkle_root,omitempty"`
	Error               string  `json:"error,omitempty"`
}

func verifyOnlineProof(report *verifier.VerifyReport, ledgerURL string) (*onlineProofResponse, error) {
	if ledgerURL == "" {
		ledgerURL = os.Getenv("HELM_LEDGER_URL")
	}
	if ledgerURL == "" {
		ledgerURL = "https://mindburn.org/api/proof/verify"
	}

	body, err := json.Marshal(map[string]any{
		"envelope_id": report.EnvelopeID,
		"sealed_at":   report.SealedAt,
		"merkle_root": report.MerkleRoot,
		"anchor_index": func() any {
			if report.AnchorIndex == nil {
				return nil
			}
			return *report.AnchorIndex
		}(),
		"offline_verified": report.Verified,
	})
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(ledgerURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("public proof API unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("public proof API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var proof onlineProofResponse
	if err := json.NewDecoder(resp.Body).Decode(&proof); err != nil {
		return nil, fmt.Errorf("invalid public proof response: %w", err)
	}
	return &proof, nil
}

func mergeOnlineProof(report *verifier.VerifyReport, proof *onlineProofResponse) {
	if proof.EnvelopeID != "" {
		report.EnvelopeID = proof.EnvelopeID
	}
	if proof.SealedAt != "" {
		report.SealedAt = proof.SealedAt
	}
	if proof.MerkleRoot != "" {
		report.MerkleRoot = proof.MerkleRoot
	}
	if proof.SignatureTotalCount > 0 {
		report.SignatureTotalCount = proof.SignatureTotalCount
		report.SignatureValidCount = proof.SignatureValidCount
	}
	if proof.AnchorIndex != nil {
		report.AnchorIndex = proof.AnchorIndex
	}
}
