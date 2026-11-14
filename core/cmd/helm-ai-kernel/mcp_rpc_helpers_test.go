package main

import (
	"context"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

func handleMCPRPCRequest(req *mcpRPCRequest, catalog *mcppkg.ToolCatalog, executor mcppkg.ToolExecutor) (*mcpRPCResponse, error) {
	ctx := withMCPTransportIdentity(context.Background(), "mcp-stdio", "mcp-stdio-transport")
	return handleMCPRPCRequestWithContext(ctx, req, catalog, executor)
}
