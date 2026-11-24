package capabilities

// StdioMCPClient records the command and arguments for an MCP stdio client.
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
