package timesfm

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Connector identity and initialisation
// ---------------------------------------------------------------------------

func TestNewConnector_DefaultID(t *testing.T) {
	c := NewConnector(Config{})
	if c.ID() != "timesfm-v1" {
		t.Errorf("ID() = %q, want %q", c.ID(), "timesfm-v1")
	}
}

func TestNewConnector_CustomID(t *testing.T) {
	c := NewConnector(Config{ConnectorID: "timesfm-custom"})
	if c.ID() != "timesfm-custom" {
		t.Errorf("ID() = %q, want %q", c.ID(), "timesfm-custom")
	}
}

func TestNewConnector_GraphEmptyOnInit(t *testing.T) {
	c := NewConnector(Config{})
	if c.GraphLen() != 0 {
		t.Errorf("fresh graph should be empty, got %d nodes", c.GraphLen())
	}
}

func TestNewConnector_ClientInitialised(t *testing.T) {
	c := NewConnector(Config{APIKey: "test-key"})
	if c.client == nil {
		t.Fatal("client not initialised")
	}
}

// ---------------------------------------------------------------------------
// Execute — dispatch and graph recording
// ---------------------------------------------------------------------------

func TestExecute_Forecast_WritesIntentNode(t *testing.T) {
	c := NewConnector(Config{})
	ctx := context.Background()

	_, err := c.Execute(ctx, ToolForecast, map[string]any{
		"symbol":        "BTC-USD",
		"target_series": "realized_volatility",
		"history_days":  float64(30),
		"horizon_steps": float64(10),
	})
	// stub client always errors — that is expected
	if err == nil {
		t.Fatal("expected error from stub client")
	}

	if c.GraphLen() < 1 {
		t.Error("expected at least 1 INTENT node in graph after stub failure")
	}

	nodes := c.GraphNodes()
	foundIntent := false
	for _, n := range nodes {
		if n.Kind == "INTENT" {
			foundIntent = true
			break
		}
	}
	if !foundIntent {
		t.Error("no INTENT node recorded in graph")
	}
}

func TestExecute_UnknownTool_ReturnsError(t *testing.T) {
	c := NewConnector(Config{})
	ctx := context.Background()

	_, err := c.Execute(ctx, "timesfm.unknown_tool", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	want := `timesfm: unknown tool "timesfm.unknown_tool"`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestExecute_RateLimit_BlocksAfterLimit(t *testing.T) {
	c := NewConnector(Config{RatePerMinute: 2})
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		_, _ = c.Execute(ctx, ToolForecast, map[string]any{"symbol": "BTC-USD"})
	}
	_, err := c.Execute(ctx, ToolForecast, map[string]any{"symbol": "BTC-USD"})
	if err == nil {
		t.Fatal("expected rate limit error on 3rd call")
	}
	if !strings.Contains(err.Error(), "gate denied") {
		t.Errorf("expected gate denied error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// AllowedDataClasses
// ---------------------------------------------------------------------------

func TestAllowedDataClasses(t *testing.T) {
	classes := AllowedDataClasses()
	if len(classes) != 1 {
		t.Fatalf("got %d data classes, want 1", len(classes))
	}
	if classes[0] != "timesfm.series.forecast" {
		t.Errorf("unexpected data class: %s", classes[0])
	}
}

// ---------------------------------------------------------------------------
// Types — JSON round-trip
// ---------------------------------------------------------------------------

func TestForecastRequest_JSONRoundTrip(t *testing.T) {
	req := ForecastRequest{
		Symbol:       "ETH-USD",
		TargetSeries: "volume",
		HistoryDays:  60,
		HorizonSteps: 20,
		Quantiles:    []float64{0.1, 0.5, 0.9},
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ForecastRequest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Symbol != req.Symbol || got.TargetSeries != req.TargetSeries {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, req)
	}
	if len(got.Quantiles) != 3 {
		t.Errorf("expected 3 quantiles, got %d", len(got.Quantiles))
	}
}

func TestForecastResult_JSONRoundTrip(t *testing.T) {
	result := ForecastResult{
		SnapshotID:   "snap-001",
		Symbol:       "BTC-USD",
		TargetSeries: "realized_volatility",
		HorizonSteps: 10,
		ModelRef:     "timesfm-1.0-200m",
		FeatureRefs:  []string{"close", "volume"},
		ContentHash:  "cafecafe",
		GeneratedAt:  1700000000000,
		Quantiles: map[string][]float64{
			"p10": {0.01, 0.02},
			"p50": {0.05, 0.06},
			"p90": {0.10, 0.12},
		},
	}
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ForecastResult
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SnapshotID != result.SnapshotID || got.Symbol != result.Symbol {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, result)
	}
	if len(got.Quantiles) != 3 {
		t.Errorf("expected 3 quantile keys, got %d", len(got.Quantiles))
	}
	if len(got.FeatureRefs) != 2 {
		t.Errorf("expected 2 feature refs, got %d", len(got.FeatureRefs))
	}
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

func TestNewReceipt_Fields(t *testing.T) {
	req := &ForecastRequest{Symbol: "BTC-USD", TargetSeries: "realized_volatility"}
	result := &ForecastResult{
		SnapshotID:   "snap-999",
		Symbol:       "BTC-USD",
		TargetSeries: "realized_volatility",
		HorizonSteps: 10,
		ModelRef:     "timesfm-1.0-200m",
		FeatureRefs:  []string{"close"},
		ContentHash:  "deadbeef",
	}
	r := NewReceipt("timesfm-v1", req, result)

	if r.ConnectorID != "timesfm-v1" {
		t.Errorf("ConnectorID = %q", r.ConnectorID)
	}
	if r.ToolName != "timesfm.forecast" {
		t.Errorf("ToolName = %q", r.ToolName)
	}
	if r.SnapshotID != "snap-999" {
		t.Errorf("SnapshotID = %q", r.SnapshotID)
	}
	if r.ContentHash != "deadbeef" {
		t.Errorf("ContentHash = %q", r.ContentHash)
	}
	if r.IssuedAtUnix <= 0 {
		t.Error("IssuedAtUnix must be positive")
	}
}

func TestReceipt_Hash_Deterministic(t *testing.T) {
	req := &ForecastRequest{Symbol: "BTC-USD"}
	result := &ForecastResult{SnapshotID: "snap-1", ContentHash: "abc"}
	r := NewReceipt("timesfm-v1", req, result)
	r.IssuedAtUnix = 1700000000

	h1, err := r.Hash()
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	h2, err := r.Hash()
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	if h1 != h2 {
		t.Errorf("Hash not deterministic: %q != %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("expected 64-char hex SHA-256, got %d chars", len(h1))
	}
}

func TestContentHash_NonEmpty(t *testing.T) {
	result := &ForecastResult{SnapshotID: "snap-42", Symbol: "ETH-USD"}
	h, err := ContentHash(result)
	if err != nil {
		t.Fatalf("ContentHash error: %v", err)
	}
	if len(h) != 64 {
		t.Errorf("expected 64-char hex SHA-256, got %d chars", len(h))
	}
}

func TestContentHash_DifferentInputs_DifferentHashes(t *testing.T) {
	r1 := &ForecastResult{SnapshotID: "snap-1"}
	r2 := &ForecastResult{SnapshotID: "snap-2"}
	h1, _ := ContentHash(r1)
	h2, _ := ContentHash(r2)
	if h1 == h2 {
		t.Error("different inputs produced the same content hash")
	}
}

// ---------------------------------------------------------------------------
// Client request building (no real HTTP)
// ---------------------------------------------------------------------------

func TestNewClient_Initialises(t *testing.T) {
	c := NewClient("key-abc")
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	if c.apiKey != "key-abc" {
		t.Errorf("apiKey = %q, want %q", c.apiKey, "key-abc")
	}
}

func TestNewClientWithBaseURL_SetsURL(t *testing.T) {
	c := NewClientWithBaseURL("key", "https://custom.endpoint")
	if c.baseURL != "https://custom.endpoint" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
}

func TestClient_Forecast_ReturnsStubError(t *testing.T) {
	c := NewClient("key")
	_, err := c.Forecast(context.Background(), &ForecastRequest{Symbol: "BTC-USD"})
	if err == nil {
		t.Fatal("expected stub error")
	}
	if !strings.Contains(err.Error(), "stub") {
		t.Errorf("expected stub error message, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// param helpers
// ---------------------------------------------------------------------------

func TestStringParam_Present(t *testing.T) {
	params := map[string]any{"key": "BTC-USD"}
	if got := stringParam(params, "key"); got != "BTC-USD" {
		t.Errorf("stringParam = %q, want %q", got, "BTC-USD")
	}
}

func TestStringParam_Missing(t *testing.T) {
	if got := stringParam(map[string]any{}, "missing"); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestIntParam_Present(t *testing.T) {
	params := map[string]any{"steps": float64(20)}
	if got := intParam(params, "steps", 0); got != 20 {
		t.Errorf("intParam = %d, want 20", got)
	}
}

func TestIntParam_Default(t *testing.T) {
	if got := intParam(map[string]any{}, "steps", 10); got != 10 {
		t.Errorf("expected default 10, got %d", got)
	}
}

func TestFloat64SliceParam_Present(t *testing.T) {
	params := map[string]any{"q": []float64{0.1, 0.5, 0.9}}
	got := float64SliceParam(params, "q", nil)
	if len(got) != 3 {
		t.Errorf("expected 3 quantiles, got %d", len(got))
	}
}

func TestFloat64SliceParam_AnySlice(t *testing.T) {
	params := map[string]any{"q": []any{float64(0.1), float64(0.9)}}
	got := float64SliceParam(params, "q", nil)
	if len(got) != 2 {
		t.Errorf("expected 2 quantiles, got %d", len(got))
	}
}

func TestFloat64SliceParam_Default(t *testing.T) {
	def := []float64{0.1, 0.5, 0.9}
	got := float64SliceParam(map[string]any{}, "q", def)
	if len(got) != 3 {
		t.Errorf("expected 3 default quantiles, got %d", len(got))
	}
}
