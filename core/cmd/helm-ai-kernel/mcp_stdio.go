package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

type mcpRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpRPCResponse struct {
	JSONRPC string       `json:"jsonrpc"`
	ID      any          `json:"id,omitempty"`
	Result  any          `json:"result,omitempty"`
	Error   *mcpRPCError `json:"error,omitempty"`
}

type mcpRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func serveLocalMCPStdioWithDataDirAndPolicy(stdin io.Reader, stdout io.Writer, dataDir string, policyGraph *prg.Graph) error {
	catalog, executor, err := newLocalMCPRuntimeWithDataDirAndPolicy(dataDir, policyGraph)
	if err != nil {
		return err
	}

	reader := bufio.NewReader(stdin)
	for {
		req, err := readMCPRequest(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		resp, err := handleMCPRPCRequest(req, catalog, executor.Execute)
		if err != nil {
			return err
		}
		if resp == nil {
			continue
		}
		if err := writeMCPResponse(stdout, resp); err != nil {
			return err
		}
	}
}

func readMCPRequest(reader *bufio.Reader) (*mcpRPCRequest, error) {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "{") {
			var req mcpRPCRequest
			if err := json.Unmarshal([]byte(trimmed), &req); err != nil {
				return nil, fmt.Errorf("decode stdio request: %w", err)
			}
			return &req, nil
		}

		headers := map[string]string{}
		for trimmed != "" {

			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid MCP header %q", trimmed)
			}
			headers[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])

			nextLine, readErr := reader.ReadString('\n')
			if readErr != nil {
				return nil, readErr
			}
			trimmed = strings.TrimSpace(nextLine)
			if trimmed == "" {
				break
			}
		}

		contentLength, err := strconv.Atoi(headers["content-length"])
		if err != nil || contentLength <= 0 {
			return nil, fmt.Errorf("missing or invalid Content-Length header")
		}

		payload := make([]byte, contentLength)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, fmt.Errorf("read MCP payload: %w", err)
		}

		var req mcpRPCRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, fmt.Errorf("decode MCP payload: %w", err)
		}
		return &req, nil
	}
}

func writeMCPResponse(stdout io.Writer, resp *mcpRPCResponse) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("encode MCP response: %w", err)
	}
	if len(data)+1 > mcppkg.MaxResponseBytes {
		bounded := &mcpRPCResponse{
			JSONRPC: "2.0",
			ID:      resp.ID,
			Error:   &mcpRPCError{Code: -32000, Message: string(contracts.ReasonDataEgressBlocked)},
		}
		data, err = json.Marshal(bounded)
		if err == nil && len(data)+1 > mcppkg.MaxResponseBytes {
			bounded.ID = nil
			data, err = json.Marshal(bounded)
		}
		if err != nil || len(data)+1 > mcppkg.MaxResponseBytes {
			return fmt.Errorf("encode bounded MCP response")
		}
	}

	// MCP stdio transport: newline-delimited JSON (one JSON object per line).
	if _, err := stdout.Write(data); err != nil {
		return err
	}
	_, err = fmt.Fprint(stdout, "\n")
	return err
}

func handleMCPRPCRequest(req *mcpRPCRequest, catalog *mcppkg.ToolCatalog, executor mcppkg.ToolExecutor) (*mcpRPCResponse, error) {
	response := &mcpRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &params)

		protocolVersion, ok := mcppkg.NegotiateProtocolVersion(params.ProtocolVersion)
		if !ok {
			response.Error = &mcpRPCError{Code: -32602, Message: fmt.Sprintf("unsupported protocol version %q", params.ProtocolVersion)}
			return response, nil
		}

		response.Result = map[string]any{
			"protocolVersion": protocolVersion,
			"serverInfo": map[string]any{
				"name":    "helm-governance",
				"title":   "HELM Governance",
				"version": displayVersion(),
			},
			"capabilities": map[string]any{
				"tools": map[string]any{
					"listChanged": false,
				},
			},
			"instructions": "HELM governs tool execution, emits receipts, and exposes a deterministic proof surface.",
		}
		return response, nil

	case "notifications/initialized":
		return nil, nil

	case "ping":
		response.Result = map[string]any{}
		return response, nil

	case "tools/list":
		tools, err := catalog.Search(context.Background(), "")
		if err != nil {
			response.Error = &mcpRPCError{Code: -32603, Message: err.Error()}
			return response, nil
		}

		payload := make([]map[string]any, 0, len(tools))
		for _, tool := range tools {
			payload = append(payload, mcppkg.ToolDescriptorPayload(tool))
		}
		response.Result = map[string]any{"tools": payload}
		return response, nil

	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		decoder := json.NewDecoder(bytes.NewReader(req.Params))
		decoder.UseNumber()
		if err := decoder.Decode(&params); err != nil {
			response.Error = &mcpRPCError{Code: -32602, Message: "invalid tools/call params"}
			return response, nil
		}

		tool, ok := catalog.Lookup(params.Name)
		if !ok {
			response.Error = &mcpRPCError{Code: -32602, Message: "tool not found"}
			return response, nil
		}
		if _, err := mcppkg.ValidateToolArguments(tool, params.Arguments); err != nil {
			if errors.Is(err, canonicalize.ErrNonInteroperableNumber) {
				response.Error = &mcpRPCError{Code: -32000, Message: string(contracts.ReasonDataEgressBlocked)}
				return response, nil
			}
			response.Error = &mcpRPCError{Code: -32602, Message: "PEP validation failed"}
			return response, nil
		}

		execReq := mcppkg.ToolExecutionRequest{
			ToolName:       params.Name,
			Arguments:      params.Arguments,
			SessionID:      "mcp-stdio",
			PrincipalID:    "mcp-stdio",
			CredentialHash: canonicalize.HashBytes([]byte("mcp-stdio-transport")),
		}
		// NOTE: Delegation context (X-HELM-Delegation-*) is only available via
		// HTTP transport headers and is handled by the Gateway's HTTP server.
		// The stdio transport does not support delegation headers.

		execResp, err := executor(context.Background(), execReq)
		if err != nil {
			if execResp.IsError && execResp.ProtectedArgsHash != "" {
				response.Result = mcppkg.ToolResultPayload(execResp)
				return response, nil
			}
			response.Error = &mcpRPCError{Code: -32603, Message: "tool execution failed"}
			return response, nil
		}
		if !execResp.IsError && execResp.ProtectedArgsHash == "" {
			response.Error = &mcpRPCError{Code: -32603, Message: "governed execution did not attest protected arguments"}
			return response, nil
		}

		response.Result = mcppkg.ToolResultPayload(execResp)
		return response, nil

	default:
		response.Error = &mcpRPCError{
			Code:    -32601,
			Message: fmt.Sprintf("method %q not found", req.Method),
		}
		return response, nil
	}
}
