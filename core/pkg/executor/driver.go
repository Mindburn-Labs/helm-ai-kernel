package executor

import (
	"context"
	"fmt"
)

// ToolDriver abstracts the actual execution of an effect.
// This allows the Executor to support both Native (Go code) and MCP (Remote) tools.
type ToolDriver interface {
	// Execute performs the capability action with the given payload.
	Execute(ctx context.Context, toolName string, params map[string]any) (any, error)
}

// MCPDriver executes tools via the Model Context Protocol.
type MCPDriver struct {
	client interface {
		Call(tool string, params map[string]any) (any, error)
	}
}

func NewMCPDriver(client interface {
	Call(tool string, params map[string]any) (any, error)
}) *MCPDriver {
	return &MCPDriver{client: client}
}

func (m *MCPDriver) Execute(ctx context.Context, toolName string, params map[string]any) (any, error) {
	if m.client == nil {
		return nil, fmt.Errorf("mcp driver: client not configured")
	}
	return m.client.Call(toolName, params)
}
