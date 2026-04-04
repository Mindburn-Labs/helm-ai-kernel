package vibevoice

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
	if c.ID() != "vibevoice-v1" {
		t.Errorf("ID() = %q, want %q", c.ID(), "vibevoice-v1")
	}
}

func TestNewConnector_CustomID(t *testing.T) {
	c := NewConnector(Config{ConnectorID: "vibevoice-custom"})
	if c.ID() != "vibevoice-custom" {
		t.Errorf("ID() = %q, want %q", c.ID(), "vibevoice-custom")
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

func TestExecute_Transcribe_WritesIntentNode(t *testing.T) {
	c := NewConnector(Config{})
	ctx := context.Background()

	_, err := c.Execute(ctx, ToolTranscribe, map[string]any{
		"audio_url":     "https://example.com/audio.wav",
		"language_code": "en-US",
		"encoding":      "wav",
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

	_, err := c.Execute(ctx, "vibevoice.unknown_tool", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	want := `vibevoice: unknown tool "vibevoice.unknown_tool"`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestExecute_RateLimit_BlocksAfterLimit(t *testing.T) {
	c := NewConnector(Config{RatePerMinute: 3})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_, _ = c.Execute(ctx, ToolTranscribe, map[string]any{"audio_url": "x"})
	}
	_, err := c.Execute(ctx, ToolTranscribe, map[string]any{"audio_url": "x"})
	if err == nil {
		t.Fatal("expected rate limit error on 4th call")
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
	if classes[0] != "vibevoice.audio.transcribe" {
		t.Errorf("unexpected data class: %s", classes[0])
	}
}

// ---------------------------------------------------------------------------
// Types — JSON round-trip
// ---------------------------------------------------------------------------

func TestTranscriptionRequest_JSONRoundTrip(t *testing.T) {
	req := TranscriptionRequest{
		AudioURL:     "https://example.com/audio.wav",
		LanguageCode: "en-US",
		SampleRate:   16000,
		Encoding:     "wav",
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got TranscriptionRequest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.AudioURL != req.AudioURL || got.LanguageCode != req.LanguageCode ||
		got.SampleRate != req.SampleRate || got.Encoding != req.Encoding {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, req)
	}
}

func TestTranscriptionResult_JSONRoundTrip(t *testing.T) {
	result := TranscriptionResult{
		TranscriptID: "tr-123",
		Text:         "hello world",
		Language:     "en",
		DurationMs:   3500,
		Confidence:   0.97,
		ContentHash:  "abc123",
		Segments: []TranscriptSegment{
			{StartMs: 0, EndMs: 1000, Text: "hello", Confidence: 0.99},
			{StartMs: 1000, EndMs: 2000, Text: "world", Speaker: "A", Confidence: 0.95},
		},
	}
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got TranscriptionResult
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.TranscriptID != result.TranscriptID || got.Text != result.Text {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, result)
	}
	if len(got.Segments) != 2 {
		t.Errorf("expected 2 segments, got %d", len(got.Segments))
	}
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

func TestNewReceipt_Fields(t *testing.T) {
	req := &TranscriptionRequest{AudioURL: "https://example.com/audio.wav", LanguageCode: "en-US"}
	result := &TranscriptionResult{
		TranscriptID: "tr-999",
		Language:     "en",
		DurationMs:   5000,
		Confidence:   0.95,
		ContentHash:  "deadbeef",
	}
	r := NewReceipt("vibevoice-v1", req, result)

	if r.ConnectorID != "vibevoice-v1" {
		t.Errorf("ConnectorID = %q", r.ConnectorID)
	}
	if r.ToolName != "vibevoice.transcribe" {
		t.Errorf("ToolName = %q", r.ToolName)
	}
	if r.TranscriptID != "tr-999" {
		t.Errorf("TranscriptID = %q", r.TranscriptID)
	}
	if r.ContentHash != "deadbeef" {
		t.Errorf("ContentHash = %q", r.ContentHash)
	}
	if r.IssuedAtUnix <= 0 {
		t.Error("IssuedAtUnix must be positive")
	}
}

func TestReceipt_Hash_Deterministic(t *testing.T) {
	req := &TranscriptionRequest{AudioURL: "https://example.com/audio.wav"}
	result := &TranscriptionResult{TranscriptID: "tr-1", ContentHash: "abc"}
	r := NewReceipt("vibevoice-v1", req, result)
	// Fix the timestamp so hash is deterministic within the test.
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
	result := &TranscriptionResult{TranscriptID: "tr-42", Text: "hello"}
	h, err := ContentHash(result)
	if err != nil {
		t.Fatalf("ContentHash error: %v", err)
	}
	if len(h) != 64 {
		t.Errorf("expected 64-char hex SHA-256, got %d chars", len(h))
	}
}

func TestContentHash_DifferentInputs_DifferentHashes(t *testing.T) {
	r1 := &TranscriptionResult{Text: "hello"}
	r2 := &TranscriptionResult{Text: "world"}
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

func TestClient_Transcribe_ReturnsStubError(t *testing.T) {
	c := NewClient("key")
	_, err := c.Transcribe(context.Background(), &TranscriptionRequest{AudioURL: "x"})
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
	params := map[string]any{"key": "value"}
	if got := stringParam(params, "key"); got != "value" {
		t.Errorf("stringParam = %q, want %q", got, "value")
	}
}

func TestStringParam_Missing(t *testing.T) {
	if got := stringParam(map[string]any{}, "missing"); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestIntParam_Present(t *testing.T) {
	params := map[string]any{"rate": float64(22050)}
	if got := intParam(params, "rate", 0); got != 22050 {
		t.Errorf("intParam = %d, want 22050", got)
	}
}

func TestIntParam_Default(t *testing.T) {
	if got := intParam(map[string]any{}, "rate", 16000); got != 16000 {
		t.Errorf("expected default 16000, got %d", got)
	}
}
