package capabilities

import ()

// StdioMCPClient talks to an MCP server via stdio.
type StdioMCPClient struct {
	Command string
	Args    []string
}

type mcpRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
	ID      int            `json:"id"`
}
