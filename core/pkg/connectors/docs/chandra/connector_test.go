package chandra

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
	if c.ID() != "chandra-v1" {
		t.Errorf("ID() = %q, want %q", c.ID(), "chandra-v1")
	}
}

func TestNewConnector_CustomID(t *testing.T) {
	c := NewConnector(Config{ConnectorID: "chandra-custom"})
	if c.ID() != "chandra-custom" {
		t.Errorf("ID() = %q, want %q", c.ID(), "chandra-custom")
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

func TestExecute_ParseDocument_WritesIntentNode(t *testing.T) {
	c := NewConnector(Config{})
	ctx := context.Background()

	_, err := c.Execute(ctx, ToolParseDocument, map[string]any{
		"document_url": "https://example.com/doc.pdf",
		"media_type":   "application/pdf",
		"ocr_enabled":  true,
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

	_, err := c.Execute(ctx, "chandra.unknown_tool", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	want := `chandra: unknown tool "chandra.unknown_tool"`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestExecute_RateLimit_BlocksAfterLimit(t *testing.T) {
	c := NewConnector(Config{RatePerMinute: 2})
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		_, _ = c.Execute(ctx, ToolParseDocument, map[string]any{"document_url": "x"})
	}
	_, err := c.Execute(ctx, ToolParseDocument, map[string]any{"document_url": "x"})
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
	if classes[0] != "chandra.document.parse" {
		t.Errorf("unexpected data class: %s", classes[0])
	}
}

// ---------------------------------------------------------------------------
// Types — JSON round-trip
// ---------------------------------------------------------------------------

func TestParseRequest_JSONRoundTrip(t *testing.T) {
	req := ParseRequest{
		DocumentURL: "https://example.com/doc.pdf",
		MediaType:   "application/pdf",
		Options: ParseOptions{
			ExtractTables:  true,
			OCREnabled:     true,
			LayoutAnalysis: false,
		},
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ParseRequest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.DocumentURL != req.DocumentURL || got.MediaType != req.MediaType {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, req)
	}
	if got.Options.ExtractTables != true || got.Options.OCREnabled != true {
		t.Errorf("options round-trip mismatch: got %+v", got.Options)
	}
}

func TestParseResult_JSONRoundTrip(t *testing.T) {
	result := ParseResult{
		DocumentID:  "doc-abc",
		ContentHash: "cafebabe",
		Pages: []PageResult{
			{PageNum: 1, Text: "page one content", Layout: "single-column"},
			{PageNum: 2, Text: "page two content"},
		},
		Tables: []TableResult{
			{
				PageNum: 1,
				Headers: []string{"Name", "Value"},
				Rows:    [][]string{{"foo", "bar"}},
			},
		},
		Metadata: DocMetadata{
			Title:     "Test Doc",
			Author:    "Alice",
			PageCount: 2,
			WordCount: 100,
		},
	}
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ParseResult
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.DocumentID != result.DocumentID {
		t.Errorf("DocumentID mismatch: %q", got.DocumentID)
	}
	if len(got.Pages) != 2 {
		t.Errorf("expected 2 pages, got %d", len(got.Pages))
	}
	if len(got.Tables) != 1 || len(got.Tables[0].Headers) != 2 {
		t.Errorf("tables round-trip mismatch")
	}
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

func TestNewReceipt_Fields(t *testing.T) {
	req := &ParseRequest{DocumentURL: "https://example.com/doc.pdf", MediaType: "application/pdf"}
	result := &ParseResult{
		DocumentID:  "doc-999",
		ContentHash: "deadbeef",
		Metadata:    DocMetadata{PageCount: 5, WordCount: 2000},
	}
	r := NewReceipt("chandra-v1", req, result)

	if r.ConnectorID != "chandra-v1" {
		t.Errorf("ConnectorID = %q", r.ConnectorID)
	}
	if r.ToolName != "chandra.parse_document" {
		t.Errorf("ToolName = %q", r.ToolName)
	}
	if r.DocumentID != "doc-999" {
		t.Errorf("DocumentID = %q", r.DocumentID)
	}
	if r.PageCount != 5 {
		t.Errorf("PageCount = %d, want 5", r.PageCount)
	}
	if r.ContentHash != "deadbeef" {
		t.Errorf("ContentHash = %q", r.ContentHash)
	}
	if r.IssuedAtUnix <= 0 {
		t.Error("IssuedAtUnix must be positive")
	}
}

func TestReceipt_Hash_Deterministic(t *testing.T) {
	req := &ParseRequest{DocumentURL: "https://example.com/doc.pdf"}
	result := &ParseResult{DocumentID: "doc-1", ContentHash: "abc"}
	r := NewReceipt("chandra-v1", req, result)
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
	result := &ParseResult{DocumentID: "doc-42"}
	h, err := ContentHash(result)
	if err != nil {
		t.Fatalf("ContentHash error: %v", err)
	}
	if len(h) != 64 {
		t.Errorf("expected 64-char hex SHA-256, got %d chars", len(h))
	}
}

func TestContentHash_DifferentInputs_DifferentHashes(t *testing.T) {
	r1 := &ParseResult{DocumentID: "doc-1"}
	r2 := &ParseResult{DocumentID: "doc-2"}
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

func TestClient_ParseDocument_ReturnsStubError(t *testing.T) {
	c := NewClient("key")
	_, err := c.ParseDocument(context.Background(), &ParseRequest{DocumentURL: "x"})
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

func TestBoolParam_Present(t *testing.T) {
	params := map[string]any{"ocr": true}
	if got := boolParam(params, "ocr"); !got {
		t.Error("expected true")
	}
}

func TestBoolParam_Missing(t *testing.T) {
	if got := boolParam(map[string]any{}, "ocr"); got {
		t.Error("expected false for missing key")
	}
}
