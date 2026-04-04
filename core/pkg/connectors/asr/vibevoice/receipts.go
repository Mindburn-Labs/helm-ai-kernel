package vibevoice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Receipt is the auditable record of a completed transcription operation.
type Receipt struct {
	ConnectorID  string `json:"connector_id"`
	ToolName     string `json:"tool_name"`
	TranscriptID string `json:"transcript_id"`
	AudioURL     string `json:"audio_url"`
	Language     string `json:"language"`
	DurationMs   int64  `json:"duration_ms"`
	Confidence   float64 `json:"confidence"`
	ContentHash  string `json:"content_hash"`
	IssuedAtUnix int64  `json:"issued_at_unix"`
}

// NewReceipt constructs a Receipt from a TranscriptionResult.
func NewReceipt(connectorID string, req *TranscriptionRequest, result *TranscriptionResult) *Receipt {
	return &Receipt{
		ConnectorID:  connectorID,
		ToolName:     "vibevoice.transcribe",
		TranscriptID: result.TranscriptID,
		AudioURL:     req.AudioURL,
		Language:     result.Language,
		DurationMs:   result.DurationMs,
		Confidence:   result.Confidence,
		ContentHash:  result.ContentHash,
		IssuedAtUnix: time.Now().Unix(),
	}
}

// Hash returns the SHA-256 hex digest of the receipt's canonical JSON representation.
func (r *Receipt) Hash() (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("vibevoice: receipt hash: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ContentHash computes a deterministic SHA-256 hex digest over the given value's
// JSON encoding.  It is used to populate TranscriptionResult.ContentHash before a
// Receipt is created.
func ContentHash(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("vibevoice: content hash: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// provenanceHash computes a SHA-256 digest binding the connector ID, intent bytes,
// and response bytes together.  This mirrors the role of
// connector.ComputeProvenanceTag in the full framework.
func provenanceHash(connectorID string, intentData, responseData []byte) (string, error) {
	h := sha256.New()
	h.Write([]byte(connectorID))
	h.Write(intentData)
	h.Write(responseData)
	return hex.EncodeToString(h.Sum(nil)), nil
}
