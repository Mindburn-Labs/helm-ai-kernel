// Package timesfm provides the HELM connector for the TimesFM probabilistic forecasting API.
//
// Architecture:
//   - types.go:     Request/response types for forecasting operations
//   - client.go:    HTTP client for the TimesFM API (stub implementation)
//   - receipts.go:  Receipt generation for forecasting operations
//   - connector.go: Self-contained connector with Forecast tool
package timesfm

// ForecastRequest is the input for a probabilistic forecast operation.
type ForecastRequest struct {
	Symbol       string    `json:"symbol"`
	TargetSeries string    `json:"target_series"` // realized_volatility, volume, funding_rate, liquidity
	HistoryDays  int       `json:"history_days"`
	HorizonSteps int       `json:"horizon_steps"`
	Quantiles    []float64 `json:"quantiles"` // e.g., [0.1, 0.5, 0.9]
}

// ForecastResult is the output of a completed probabilistic forecast.
type ForecastResult struct {
	SnapshotID   string               `json:"snapshot_id"`
	Symbol       string               `json:"symbol"`
	TargetSeries string               `json:"target_series"`
	HorizonSteps int                  `json:"horizon_steps"`
	Quantiles    map[string][]float64 `json:"quantiles"` // "p10": [...], "p50": [...], "p90": [...]
	ModelRef     string               `json:"model_ref"`
	FeatureRefs  []string             `json:"feature_refs"`
	ContentHash  string               `json:"content_hash"`
	GeneratedAt  int64                `json:"generated_at_unix_ms"`
}

// intentPayload is the graph INTENT node payload for a timesfm action.
type intentPayload struct {
	Type     string         `json:"type"`
	ToolName string         `json:"tool_name"`
	Params   map[string]any `json:"params,omitempty"`
}

// effectPayload is the graph EFFECT node payload after a timesfm action.
type effectPayload struct {
	Type           string `json:"type"`
	ToolName       string `json:"tool_name"`
	ContentHash    string `json:"content_hash"`
	ProvenanceHash string `json:"provenance_hash,omitempty"`
}
