package conform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ReportSignature represents a signed conformance report per §10.
type ReportSignature struct {
	IndexHash        string    `json:"index_hash"`
	ScoreHash        string    `json:"score_hash"`
	PolicyHash       string    `json:"policy_hash"`
	SchemaBundleHash string    `json:"schema_bundle_hash"`
	Signature        string    `json:"signature"`
	SignedAt         time.Time `json:"signed_at"`
	SignerID         string    `json:"signer_id"`
}

// SignerFunc is a function that signs bytes and returns a hex-encoded signature.
type SignerFunc func(data []byte) (string, error)

// SignReport generates the conformance report signature per §10.
// The signature covers: 00_INDEX.json hash, 01_SCORE.json hash,
// policy_hash, and schema bundle hashes.
func SignReport(evidenceDir string, policyHash string, schemaBundleHash string, signerID string, signer SignerFunc) (*ReportSignature, error) {
	// Read and hash 00_INDEX.json
	indexData, err := os.ReadFile(filepath.Join(evidenceDir, "00_INDEX.json"))
	if err != nil {
		return nil, fmt.Errorf("read 00_INDEX.json: %w", err)
	}
	indexHash := sha256Hash(indexData)

	// Read and hash 01_SCORE.json
	scoreData, err := os.ReadFile(filepath.Join(evidenceDir, "01_SCORE.json"))
	if err != nil {
		return nil, fmt.Errorf("read 01_SCORE.json: %w", err)
	}
	scoreHash := sha256Hash(scoreData)

	// Build canonical signing payload
	payload := map[string]string{
		"index_hash":         indexHash,
		"score_hash":         scoreHash,
		"policy_hash":        policyHash,
		"schema_bundle_hash": schemaBundleHash,
	}
	canonicalPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal signing payload: %w", err)
	}

	// Sign
	sig, err := signer(canonicalPayload)
	if err != nil {
		return nil, fmt.Errorf("sign report: %w", err)
	}

	reportSig := &ReportSignature{
		IndexHash:        indexHash,
		ScoreHash:        scoreHash,
		PolicyHash:       policyHash,
		SchemaBundleHash: schemaBundleHash,
		Signature:        sig,
		SignedAt:         time.Now().UTC(),
		SignerID:         signerID,
	}

	// Write signature to 07_ATTESTATIONS/conformance_report.sig
	sigData, err := json.MarshalIndent(reportSig, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal signature: %w", err)
	}

	sigPath := filepath.Join(evidenceDir, "07_ATTESTATIONS", "conformance_report.sig")
	if err := os.WriteFile(sigPath, sigData, 0600); err != nil {
		return nil, fmt.Errorf("write signature: %w", err)
	}

	return reportSig, nil
}

// VerifyReport validates a signed conformance report.
func VerifyReport(evidenceDir string, verifier func(data []byte, sig string) error) error {
	// Read signature
	sigData, err := os.ReadFile(filepath.Join(evidenceDir, "07_ATTESTATIONS", "conformance_report.sig"))
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}

	var reportSig ReportSignature
	if err := json.Unmarshal(sigData, &reportSig); err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}

	// Verify index hash
	indexData, err := os.ReadFile(filepath.Join(evidenceDir, "00_INDEX.json"))
	if err != nil {
		return fmt.Errorf("read 00_INDEX.json: %w", err)
	}
	if sha256Hash(indexData) != reportSig.IndexHash {
		return fmt.Errorf("00_INDEX.json hash mismatch")
	}

	// Verify score hash
	scoreData, err := os.ReadFile(filepath.Join(evidenceDir, "01_SCORE.json"))
	if err != nil {
		return fmt.Errorf("read 01_SCORE.json: %w", err)
	}
	if sha256Hash(scoreData) != reportSig.ScoreHash {
		return fmt.Errorf("01_SCORE.json hash mismatch")
	}

	// Verify cryptographic signature
	payload := map[string]string{
		"index_hash":         reportSig.IndexHash,
		"score_hash":         reportSig.ScoreHash,
		"policy_hash":        reportSig.PolicyHash,
		"schema_bundle_hash": reportSig.SchemaBundleHash,
	}
	canonicalPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	if err := verifier(canonicalPayload, reportSig.Signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

func sha256Hash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
