package mcp

import "encoding/json"

const (
	LatestProtocolVersion = "2025-11-25"
	LegacyProtocolVersion = "2025-03-26"
)

var SupportedProtocolVersions = []string{
	LatestProtocolVersion,
	"2025-06-18",
	LegacyProtocolVersion,
}

type ToolAnnotations struct {
	ReadOnlyHint    bool `json:"readOnlyHint,omitempty"`
	DestructiveHint bool `json:"destructiveHint,omitempty"`
	IdempotentHint  bool `json:"idempotentHint,omitempty"`
	OpenWorldHint   bool `json:"openWorldHint,omitempty"`
}

type ToolContentItem struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	URI      string `json:"uri,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	Name     string `json:"name,omitempty"`
}

func NegotiateProtocolVersion(requested string) (string, bool) {
	if requested == "" {
		return LatestProtocolVersion, true
	}
	for _, version := range SupportedProtocolVersions {
		if requested == version {
			return version, true
		}
	}
	return "", false
}

func ToolDescriptorPayload(tool ToolRef) map[string]any {
	payload := map[string]any{
		"name":        tool.Name,
		"description": tool.Description,
		"inputSchema": tool.Schema,
	}
	if tool.Title != "" {
		payload["title"] = tool.Title
	}
	if tool.OutputSchema != nil {
		payload["outputSchema"] = tool.OutputSchema
	}
	if annotations := toolAnnotationsPayload(tool.Annotations); len(annotations) > 0 {
		payload["annotations"] = annotations
	}
	return payload
}

func ToolResultPayload(resp ToolExecutionResponse) map[string]any {
	content := resp.ContentItems
	if len(content) == 0 && resp.Content != "" {
		content = []ToolContentItem{{Type: "text", Text: resp.Content}}
	}

	payload := map[string]any{
		"content": content,
		"isError": resp.IsError,
	}
	if len(resp.StructuredContent) > 0 {
		payload["structuredContent"] = resp.StructuredContent
	}
	if resp.ReceiptID != "" {
		payload["receipt_id"] = resp.ReceiptID
	}
	return payload
}

func StructuredTextContent(payload map[string]any, fallback string) []ToolContentItem {
	if len(payload) == 0 {
		if fallback == "" {
			return nil
		}
		return []ToolContentItem{{Type: "text", Text: fallback}}
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return []ToolContentItem{{Type: "text", Text: fallback}}
	}
	return []ToolContentItem{{Type: "text", Text: string(data)}}
}

func toolAnnotationsPayload(annotations *ToolAnnotations) map[string]any {
	if annotations == nil {
		return nil
	}
	payload := map[string]any{}
	if annotations.ReadOnlyHint {
		payload["readOnlyHint"] = true
	}
	if annotations.DestructiveHint {
		payload["destructiveHint"] = true
	}
	if annotations.IdempotentHint {
		payload["idempotentHint"] = true
	}
	if annotations.OpenWorldHint {
		payload["openWorldHint"] = true
	}
	return payload
}
