package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Catalog manages the registry of approved tools.
type Catalog interface {
	Search(ctx context.Context, query string) ([]ToolRef, error)
	Register(ctx context.Context, ref ToolRef) error
}

// ToolRef represents a tool reference for catalog search and definition.
type ToolRef struct {
	Name           string           `json:"name"`
	Title          string           `json:"title,omitempty"`
	Description    string           `json:"description"`
	ServerID       string           `json:"server_id,omitempty"`
	Schema         any              `json:"schema,omitempty"` // Legacy input schema alias for /mcp/v1/*
	OutputSchema   any              `json:"output_schema,omitempty"`
	Annotations    *ToolAnnotations `json:"annotations,omitempty"`
	RequiredScopes []string         `json:"required_scopes,omitempty"`
}

// Validate checks that a ToolRef has a non-empty Name.
func (r ToolRef) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("tool ref name is required")
	}
	return nil
}

// ToolCatalog checks compliance and stores tool definitions.
type ToolCatalog struct {
	mu    sync.RWMutex
	tools map[string]ToolRef
}

func NewToolCatalog() *ToolCatalog {
	return &ToolCatalog{
		tools: make(map[string]ToolRef),
	}
}

// NewInMemoryCatalog is a constructor alias for tests
func NewInMemoryCatalog() *ToolCatalog {
	return NewToolCatalog()
}

func (c *ToolCatalog) RegisterCommonTools() {
	tools := []ToolRef{
		{
			Name:        "file_read",
			Title:       "Read File",
			Description: "Read a UTF-8 text file from disk",
			ServerID:    "helm-governance",
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string"},
				},
				"required": []string{"path"},
			},
			OutputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":       map[string]any{"type": "string"},
					"text":       map[string]any{"type": "string"},
					"size_bytes": map[string]any{"type": "integer"},
				},
				"required": []string{"path", "text", "size_bytes"},
			},
			Annotations: &ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
			},
		},
		{
			Name:        "file_write",
			Title:       "Write File",
			Description: "Write UTF-8 text content to disk",
			ServerID:    "helm-governance",
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":    map[string]any{"type": "string"},
					"content": map[string]any{"type": "string"},
				},
				"required": []string{"path", "content"},
			},
			OutputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":          map[string]any{"type": "string"},
					"bytes_written": map[string]any{"type": "integer"},
					"status":        map[string]any{"type": "string"},
				},
				"required": []string{"path", "bytes_written", "status"},
			},
			Annotations: &ToolAnnotations{
				DestructiveHint: true,
				IdempotentHint:  true,
			},
		},
	}

	for _, ref := range tools {
		_ = c.Register(context.Background(), ref)
	}
}

// RegisterGovernanceTools registers the HELM governance tools that let
// any MCP-speaking agent request policy decisions and A2A envelope evaluation.
func (c *ToolCatalog) RegisterGovernanceTools() {
	tools := []ToolRef{
		{
			Name:        "helm.verify",
			Title:       "Verify Agent Action",
			Description: "Evaluate an agent action against HELM governance policy. Returns a cryptographic receipt with verdict, reason code, and proof graph node reference.",
			ServerID:    "helm-governance",
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"action":    map[string]any{"type": "string", "description": "The action to verify (e.g., tool name or operation ID)"},
					"principal": map[string]any{"type": "string", "description": "Identity of the agent requesting the action"},
					"resource":  map[string]any{"type": "string", "description": "Target resource for the action"},
					"args_hash": map[string]any{"type": "string", "description": "SHA-256 hash of the action arguments for deterministic verification"},
				},
				"required": []string{"action", "principal"},
			},
			OutputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"verdict":         map[string]any{"type": "string", "enum": []string{"ALLOW", "DENY"}},
					"receipt_id":      map[string]any{"type": "string"},
					"reason_code":     map[string]any{"type": "string"},
					"proofgraph_node": map[string]any{"type": "string"},
				},
				"required": []string{"verdict", "receipt_id", "reason_code"},
			},
			Annotations: &ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
			},
			RequiredScopes: []string{"mcp:tools", "helm:verify"},
		},
		{
			Name:        "helm.evaluate",
			Title:       "Evaluate A2A Envelope",
			Description: "Negotiate A2A protocol features and verify envelope signatures for cross-agent communication. Returns negotiation result with agreed features and trust assessment.",
			ServerID:    "helm-governance",
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"envelope": map[string]any{
						"type":        "object",
						"description": "The A2A envelope to evaluate",
						"properties": map[string]any{
							"envelope_id":       map[string]any{"type": "string"},
							"origin_agent_id":   map[string]any{"type": "string"},
							"target_agent_id":   map[string]any{"type": "string"},
							"required_features": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
							"offered_features":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
							"payload_hash":      map[string]any{"type": "string"},
						},
					},
					"local_features": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Features supported by the local agent for negotiation",
					},
				},
				"required": []string{"envelope"},
			},
			OutputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"accepted":        map[string]any{"type": "boolean"},
					"deny_reason":     map[string]any{"type": "string"},
					"agreed_features": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"receipt_id":      map[string]any{"type": "string"},
				},
				"required": []string{"accepted", "receipt_id"},
			},
			Annotations: &ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
			},
			RequiredScopes: []string{"mcp:tools", "helm:evaluate"},
		},
	}

	for _, ref := range tools {
		_ = c.Register(context.Background(), ref)
	}
}

func (c *ToolCatalog) Register(ctx context.Context, ref ToolRef) error {
	if err := ref.Validate(); err != nil {
		return fmt.Errorf("invalid tool ref: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tools[ref.Name] = ref
	return nil
}

func (c *ToolCatalog) Search(ctx context.Context, query string) ([]ToolRef, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var results []ToolRef
	query = strings.ToLower(query)
	for _, tool := range c.tools {
		if strings.Contains(strings.ToLower(tool.Name), query) || strings.Contains(strings.ToLower(tool.Description), query) {
			results = append(results, tool)
		}
	}
	return results, nil
}

func (c *ToolCatalog) Lookup(name string) (ToolRef, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ref, ok := c.tools[name]
	return ref, ok
}

// ToolCallReceipt tracks the execution result (for Gap 10 audit).
type ToolCallReceipt struct {
	ID        string    `json:"id"`
	ToolName  string    `json:"tool_name"`
	Inputs    string    `json:"inputs"`
	Outputs   string    `json:"outputs"`
	Metadata  string    `json:"metadata"`
	Timestamp time.Time `json:"timestamp"`
}

func (c *ToolCatalog) AuditToolCall(name string, params map[string]any, result any) (ToolCallReceipt, error) {
	inputJSON, err := json.Marshal(params)
	if err != nil {
		return ToolCallReceipt{}, fmt.Errorf("failed to marshal tool call inputs: %w", err)
	}
	outputJSON, err := json.Marshal(result)
	if err != nil {
		return ToolCallReceipt{}, fmt.Errorf("failed to marshal tool call outputs: %w", err)
	}

	return ToolCallReceipt{
		ID:        fmt.Sprintf("call-%d", time.Now().UnixNano()),
		ToolName:  name,
		Inputs:    string(inputJSON),
		Outputs:   string(outputJSON),
		Timestamp: time.Now(),
	}, nil
}
