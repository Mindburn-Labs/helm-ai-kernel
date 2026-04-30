package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	mcppkg "github.com/Mindburn-Labs/helm-oss/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
)

const maxLocalMCPFileSize = 1 << 20

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

func newLocalMCPRuntime() (*mcppkg.ToolCatalog, mcppkg.ToolExecutor, error) {
	catalog := mcppkg.NewInMemoryCatalog()
	catalog.RegisterCommonTools()

	signer, err := loadOrGenerateSigner()
	if err != nil {
		return nil, nil, err
	}

	rules := prg.NewGraph()
	for _, toolName := range []string{"file_read", "file_write"} {
		if addErr := rules.AddRule(toolName, prg.RequirementSet{
			ID:    "mcp-" + toolName,
			Logic: prg.AND,
		}); addErr != nil {
			return nil, nil, fmt.Errorf("register policy for %s: %w", toolName, addErr)
		}
	}

	guard := guardian.NewGuardian(signer, rules, nil)
	firewall := mcppkg.NewGovernanceFirewall(guard, catalog)

	return catalog, mcppkg.ToolExecutor(firewall.WrapToolHandler(runLocalMCPTool)), nil
}

func newLocalMCPGateway() (*mcppkg.Gateway, error) {
	return newConfiguredLocalMCPGateway(mcppkg.GatewayConfig{})
}

func newConfiguredLocalMCPGateway(cfg mcppkg.GatewayConfig) (*mcppkg.Gateway, error) {
	catalog, executor, err := newLocalMCPRuntime()
	if err != nil {
		return nil, err
	}

	return mcppkg.NewGateway(catalog, cfg, mcppkg.WithExecutor(executor)), nil
}

func runLocalMCPTool(ctx context.Context, req mcppkg.ToolExecutionRequest) (mcppkg.ToolExecutionResponse, error) {
	switch req.ToolName {
	case "file_read":
		path, _ := req.Arguments["path"].(string)
		resolvedPath, err := resolveLocalMCPPath(path)
		if err != nil {
			return mcppkg.ToolExecutionResponse{
				Content: err.Error(),
				IsError: true,
			}, nil
		}

		info, err := os.Stat(resolvedPath)
		if err != nil {
			return mcppkg.ToolExecutionResponse{
				Content: fmt.Sprintf("read %s: %v", resolvedPath, err),
				IsError: true,
			}, nil
		}
		if info.Size() > maxLocalMCPFileSize {
			return mcppkg.ToolExecutionResponse{
				Content: fmt.Sprintf("read %s: file exceeds %d bytes", resolvedPath, maxLocalMCPFileSize),
				IsError: true,
			}, nil
		}

		data, err := os.ReadFile(resolvedPath)
		if err != nil {
			return mcppkg.ToolExecutionResponse{
				Content: fmt.Sprintf("read %s: %v", resolvedPath, err),
				IsError: true,
			}, nil
		}

		return mcppkg.ToolExecutionResponse{
			Content: string(data),
			ContentItems: mcppkg.StructuredTextContent(map[string]any{
				"path":       resolvedPath,
				"text":       string(data),
				"size_bytes": len(data),
			}, string(data)),
			StructuredContent: map[string]any{
				"path":       resolvedPath,
				"text":       string(data),
				"size_bytes": len(data),
			},
		}, nil

	case "file_write":
		path, _ := req.Arguments["path"].(string)
		content, _ := req.Arguments["content"].(string)

		resolvedPath, err := resolveLocalMCPPath(path)
		if err != nil {
			return mcppkg.ToolExecutionResponse{
				Content: err.Error(),
				IsError: true,
			}, nil
		}

		if err := os.MkdirAll(filepath.Dir(resolvedPath), 0750); err != nil {
			return mcppkg.ToolExecutionResponse{
				Content: fmt.Sprintf("prepare %s: %v", resolvedPath, err),
				IsError: true,
			}, nil
		}
		if err := os.WriteFile(resolvedPath, []byte(content), 0600); err != nil {
			return mcppkg.ToolExecutionResponse{
				Content: fmt.Sprintf("write %s: %v", resolvedPath, err),
				IsError: true,
			}, nil
		}

		return mcppkg.ToolExecutionResponse{
			Content: fmt.Sprintf("wrote %d bytes to %s", len(content), resolvedPath),
			ContentItems: mcppkg.StructuredTextContent(map[string]any{
				"path":          resolvedPath,
				"bytes_written": len(content),
				"status":        "written",
			}, fmt.Sprintf("wrote %d bytes to %s", len(content), resolvedPath)),
			StructuredContent: map[string]any{
				"path":          resolvedPath,
				"bytes_written": len(content),
				"status":        "written",
			},
		}, nil
	default:
		return mcppkg.ToolExecutionResponse{
			Content: fmt.Sprintf("tool %q not supported", req.ToolName),
			IsError: true,
		}, nil
	}
}

func resolveLocalMCPPath(rawPath string) (string, error) {
	if strings.TrimSpace(rawPath) == "" {
		return "", fmt.Errorf("path is required")
	}

	cleaned := filepath.Clean(rawPath)
	if filepath.IsAbs(cleaned) {
		return cleaned, nil
	}

	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve working directory: %w", err)
	}
	return filepath.Join(wd, cleaned), nil
}

func serveLocalMCPStdio(stdin io.Reader, stdout io.Writer) error {
	catalog, executor, err := newLocalMCPRuntime()
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

		resp, err := handleMCPRPCRequest(req, catalog, executor)
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
		if err := json.Unmarshal(req.Params, &params); err != nil {
			response.Error = &mcpRPCError{Code: -32602, Message: "invalid tools/call params"}
			return response, nil
		}

		if _, ok := catalog.Lookup(params.Name); !ok {
			response.Error = &mcpRPCError{Code: -32602, Message: fmt.Sprintf("tool %q not found", params.Name)}
			return response, nil
		}

		execReq := mcppkg.ToolExecutionRequest{
			ToolName:  params.Name,
			Arguments: params.Arguments,
			SessionID: "mcp-stdio",
		}
		// NOTE: Delegation context (X-HELM-Delegation-*) is only available via
		// HTTP transport headers and is handled by the Gateway's HTTP server.
		// The stdio transport does not support delegation headers.

		execResp, err := executor(context.Background(), execReq)
		if err != nil {
			response.Error = &mcpRPCError{Code: -32603, Message: err.Error()}
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

func newLocalMCPHTTPServer(port int, authMode string) (*http.Server, error) {
	// SEC: Default to localhost to prevent accidental network exposure.
	mcpBind := "127.0.0.1"
	if envBind := os.Getenv("HELM_BIND_ADDR"); envBind != "" {
		mcpBind = envBind
	}
	baseURL := fmt.Sprintf("http://%s:%d", mcpBind, port)
	gateway, err := newConfiguredLocalMCPGateway(mcppkg.GatewayConfig{
		BaseURL:  baseURL,
		AuthMode: authMode,
	})
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	gateway.RegisterRoutes(mux)
	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "ok",
			"transport": "http",
		})
	}
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/healthz", healthHandler)

	handler, err := wrapMCPAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	}), authMode, baseURL)
	if err != nil {
		return nil, err
	}

	return &http.Server{
		Addr:              fmt.Sprintf("%s:%d", mcpBind, port),
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}, nil
}

func wrapMCPAuth(next http.Handler, authMode, baseURL string) (http.Handler, error) {
	switch authMode {
	case "none":
		return next, nil
	case "static-header":
		expectedKey := os.Getenv("HELM_API_KEY")
		if expectedKey == "" {
			return nil, fmt.Errorf("HELM_API_KEY must be set when --auth static-header is used")
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			provided := r.Header.Get("X-HELM-API-Key")
			if provided == "" && strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				provided = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			}
			if provided != expectedKey {
				http.Error(w, "missing or invalid MCP API key", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}), nil
	case "oauth":
		jwksURL := os.Getenv("HELM_OAUTH_JWKS_URL")
		metadataURL := strings.TrimRight(baseURL, "/") + "/.well-known/oauth-protected-resource/mcp"
		resource := strings.TrimSpace(os.Getenv("HELM_OAUTH_RESOURCE"))
		if resource == "" {
			resource = strings.TrimRight(baseURL, "/") + "/mcp"
		}

		if jwksURL != "" {
			// Production JWKS/OIDC validation.
			issuer := os.Getenv("HELM_OAUTH_ISSUER")
			audience := os.Getenv("HELM_OAUTH_AUDIENCE")
			if issuer == "" || audience == "" {
				return nil, fmt.Errorf("HELM_OAUTH_ISSUER and HELM_OAUTH_AUDIENCE must be set when HELM_OAUTH_JWKS_URL is configured")
			}
			scopes := parseMCPEnvList(os.Getenv("HELM_OAUTH_SCOPES"))

			validator := mcppkg.NewJWKSValidator(mcppkg.JWKSConfig{
				JWKSURL:  jwksURL,
				Issuer:   issuer,
				Audience: audience,
				Resource: resource,
				Scopes:   scopes,
			})

			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/.well-known/oauth-protected-resource") {
					next.ServeHTTP(w, r)
					return
				}
				authz := r.Header.Get("Authorization")
				if !strings.HasPrefix(authz, "Bearer ") {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="helm-mcp", resource_metadata="%s", resource="%s"`, metadataURL, resource))
					http.Error(w, "missing bearer token", http.StatusUnauthorized)
					return
				}
				tokenStr := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
				claims, err := validator.ValidateAuthorization(tokenStr)
				if err != nil {
					challenge := fmt.Sprintf(`Bearer realm="helm-mcp", resource_metadata="%s", resource="%s"`, metadataURL, resource)
					if validErr, ok := err.(*mcppkg.JWKSValidationError); ok && validErr.Kind == mcppkg.JWKSErrMissingScope {
						challenge += fmt.Sprintf(`, error="insufficient_scope", error_description="%s"`, validErr.Message)
					}
					w.Header().Set("WWW-Authenticate", challenge)
					http.Error(w, err.Error(), http.StatusUnauthorized)
					return
				}
				ctx := mcppkg.WithOAuthAuthorization(r.Context(), mcppkg.OAuthAuthorization{
					Scopes:    claims.Scopes,
					Resources: claims.Resources,
				})
				next.ServeHTTP(w, r.WithContext(ctx))
			}), nil
		}

		// Dev-only fallback: simple bearer token comparison.
		// Retained for one release train — will be removed in the next major version.
		expectedToken := os.Getenv("HELM_OAUTH_BEARER_TOKEN")
		if expectedToken == "" {
			return nil, fmt.Errorf("either HELM_OAUTH_JWKS_URL (production) or HELM_OAUTH_BEARER_TOKEN (dev fallback) must be set when --auth oauth is used")
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/.well-known/oauth-protected-resource") {
				next.ServeHTTP(w, r)
				return
			}
			authz := r.Header.Get("Authorization")
			provided := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
			if !strings.HasPrefix(authz, "Bearer ") || provided != expectedToken {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="helm-mcp", resource_metadata="%s", resource="%s"`, metadataURL, resource))
				http.Error(w, "missing or invalid OAuth bearer token", http.StatusUnauthorized)
				return
			}
			ctx := mcppkg.WithOAuthAuthorization(r.Context(), mcppkg.OAuthAuthorization{
				Scopes:    parseMCPEnvList(os.Getenv("HELM_OAUTH_SCOPES")),
				Resources: []string{resource},
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		}), nil
	default:
		return nil, fmt.Errorf("unknown auth mode %q", authMode)
	}
}

func parseMCPEnvList(raw string) []string {
	var values []string
	for _, value := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}
