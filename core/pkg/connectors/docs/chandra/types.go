// Package chandra provides the HELM connector for the Chandra document intelligence API.
//
// Architecture:
//   - types.go:     Request/response types for document parsing operations
//   - client.go:    HTTP client for the Chandra API (stub implementation)
//   - receipts.go:  Receipt generation for document parsing operations
//   - connector.go: Self-contained connector with ParseDocument tool
package chandra

// ParseRequest is the input for a document parse operation.
type ParseRequest struct {
	DocumentURL string       `json:"document_url"`
	MediaType   string       `json:"media_type"` // application/pdf, image/png, etc.
	Options     ParseOptions `json:"options"`
}

// ParseOptions configures which features are enabled during parsing.
type ParseOptions struct {
	ExtractTables  bool `json:"extract_tables"`
	ExtractImages  bool `json:"extract_images"`
	OCREnabled     bool `json:"ocr_enabled"`
	LayoutAnalysis bool `json:"layout_analysis"`
}

// ParseResult is the output of a completed document parse.
type ParseResult struct {
	DocumentID  string        `json:"document_id"`
	Pages       []PageResult  `json:"pages"`
	Tables      []TableResult `json:"tables,omitempty"`
	Metadata    DocMetadata   `json:"metadata"`
	ContentHash string        `json:"content_hash"`
}

// PageResult holds the extracted content for a single page.
type PageResult struct {
	PageNum int    `json:"page_num"`
	Text    string `json:"text"`
	Layout  string `json:"layout,omitempty"`
}

// TableResult holds a structured table extracted from a document page.
type TableResult struct {
	PageNum int        `json:"page_num"`
	Headers []string   `json:"headers"`
	Rows    [][]string `json:"rows"`
}

// DocMetadata holds document-level metadata.
type DocMetadata struct {
	Title     string `json:"title,omitempty"`
	Author    string `json:"author,omitempty"`
	PageCount int    `json:"page_count"`
	WordCount int    `json:"word_count"`
}

// intentPayload is the graph INTENT node payload for a chandra action.
type intentPayload struct {
	Type     string         `json:"type"`
	ToolName string         `json:"tool_name"`
	Params   map[string]any `json:"params,omitempty"`
}

// effectPayload is the graph EFFECT node payload after a chandra action.
type effectPayload struct {
	Type           string `json:"type"`
	ToolName       string `json:"tool_name"`
	ContentHash    string `json:"content_hash"`
	ProvenanceHash string `json:"provenance_hash,omitempty"`
}
