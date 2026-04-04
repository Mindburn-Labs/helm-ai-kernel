package timesfm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Receipt is the auditable record of a completed forecast operation.
type Receipt struct {
	ConnectorID  string   `json:"connector_id"`
	ToolName     string   `json:"tool_name"`
	SnapshotID   string   `json:"snapshot_id"`
	Symbol       string   `json:"symbol"`
	TargetSeries string   `json:"target_series"`
	HorizonSteps int      `json:"horizon_steps"`
	ModelRef     string   `json:"model_ref"`
	FeatureRefs  []string `json:"feature_refs"`
	ContentHash  string   `json:"content_hash"`
	IssuedAtUnix int64    `json:"issued_at_unix"`
}

// NewReceipt constructs a Receipt from a ForecastResult.
func NewReceipt(connectorID string, req *ForecastRequest, result *ForecastResult) *Receipt {
	return &Receipt{
		ConnectorID:  connectorID,
		ToolName:     "timesfm.forecast",
		SnapshotID:   result.SnapshotID,
		Symbol:       result.Symbol,
		TargetSeries: result.TargetSeries,
		HorizonSteps: result.HorizonSteps,
		ModelRef:     result.ModelRef,
		FeatureRefs:  result.FeatureRefs,
		ContentHash:  result.ContentHash,
		IssuedAtUnix: time.Now().Unix(),
	}
}

// Hash returns the SHA-256 hex digest of the receipt's canonical JSON representation.
func (r *Receipt) Hash() (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("timesfm: receipt hash: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ContentHash computes a deterministic SHA-256 hex digest over the given value's
// JSON encoding.  It is used to populate ForecastResult.ContentHash before a
// Receipt is created.
func ContentHash(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("timesfm: content hash: %w", err)
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
