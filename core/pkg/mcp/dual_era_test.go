package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func dualEraTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	catalog := NewInMemoryCatalog()
	require.NoError(t, catalog.Register(context.Background(), ToolRef{
		Name:        "audit",
		Description: "read-only audit",
		Schema:      map[string]any{"type": "object"},
	}))
	gateway := NewGateway(catalog, GatewayConfig{})
	mux := http.NewServeMux()
	gateway.RegisterRoutes(mux)
	t.Cleanup(gateway.sessions.Stop)
	return mux
}

func modernParams(version string, extra map[string]any) map[string]any {
	params := map[string]any{
		"_meta": map[string]any{
			MetaProtocolVersionKey: version,
			MetaClientInfoKey:      map[string]any{"name": "dual-era-test", "version": "1.0.0"},
		},
	}
	for k, v := range extra {
		params[k] = v
	}
	return params
}

// TestModernRequestIsServedWithoutASession is the point of the whole seam. Under
// the modern revision there is no initialize handshake and no MCP-Session-Id, and
// the request must still be answered — previously it could not be, because the
// transport only reached the JSON-RPC layer through the legacy path.
func TestModernRequestIsServedWithoutASession(t *testing.T) {
	mux := dualEraTestMux(t)

	rec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list",
		"params": modernParams(ModernProtocolVersion, nil),
	}, nil)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, ModernProtocolVersion, rec.Header().Get("MCP-Protocol-Version"),
		"the server must echo the revision it served the request under")
	// No session was issued, and none should be: a modern response that handed back
	// a session id would be inviting the client into the era it just left.
	require.Empty(t, rec.Header().Get("MCP-Session-Id"))

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Nil(t, body["error"], "a modern tools/list must not error: %v", body["error"])
	require.NotNil(t, body["result"])
}

// TestServerDiscoverReportsBothEras covers the RPC the modern revision makes
// mandatory. Reporting both eras is what makes the answer useful: a dual-era
// client can see that the newer revision is available *and* that clients pinned to
// the handshake revisions are still served.
func TestServerDiscoverReportsBothEras(t *testing.T) {
	mux := dualEraTestMux(t)

	rec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0", "id": "discover-1", "method": "server/discover",
		"params": modernParams(ModernProtocolVersion, nil),
	}, nil)

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Result DiscoverResult `json:"result"`
		Error  any            `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Nil(t, body.Error)
	require.Equal(t, "complete", body.Result.ResultType)
	require.Contains(t, body.Result.SupportedVersions, ModernProtocolVersion)
	require.Contains(t, body.Result.SupportedVersions, LatestProtocolVersion)
	require.Contains(t, body.Result.SupportedVersions, LegacyProtocolVersion)
	require.NotNil(t, body.Result.Capabilities["tools"])

	info, ok := body.Result.Meta["io.modelcontextprotocol/serverInfo"].(map[string]any)
	require.True(t, ok, "serverInfo is the one field the spec says servers SHOULD include")
	require.Equal(t, "helm-mcp-gateway", info["name"])
}

// TestUnsupportedModernVersionReturnsTheSpecifiedError pins the error contract.
// The code and the shape of `data` are what let a client retry with a version we
// both speak instead of failing the user; an HTTP 400 with prose, which is what
// this used to be, gives it nothing to act on.
func TestUnsupportedModernVersionReturnsTheSpecifiedError(t *testing.T) {
	mux := dualEraTestMux(t)

	for name, requested := range map[string]string{
		"unknown revision":           "1900-01-01",
		"handshake revision in meta": LatestProtocolVersion,
	} {
		t.Run(name, func(t *testing.T) {
			rec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
				"jsonrpc": "2.0", "id": 7, "method": "tools/list",
				"params": modernParams(requested, nil),
			}, nil)

			// The transport succeeded; the request did not. That distinction is the
			// reason this is a JSON-RPC error and not an HTTP status.
			require.Equal(t, http.StatusOK, rec.Code)

			var body struct {
				Error struct {
					Code    int            `json:"code"`
					Message string         `json:"message"`
					Data    map[string]any `json:"data"`
				} `json:"error"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, UnsupportedProtocolVersionCode, body.Error.Code)
			require.Equal(t, requested, body.Error.Data["requested"])

			supported, ok := body.Error.Data["supported"].([]any)
			require.True(t, ok, "the client needs the list to retry with")
			require.Contains(t, supported, ModernProtocolVersion)
		})
	}
}

// TestEraMismatchIsReportedRatherThanGuessed covers the case where the header and
// the `_meta` declaration disagree. Picking one silently would serve the request
// under semantics the client did not ask for, which is exactly the era-ambiguity
// the specification warns about.
func TestEraMismatchIsReportedRatherThanGuessed(t *testing.T) {
	mux := dualEraTestMux(t)

	rec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0", "id": 9, "method": "tools/list",
		"params": modernParams(ModernProtocolVersion, nil),
	}, map[string]string{"MCP-Protocol-Version": LatestProtocolVersion})

	var body struct {
		Error struct {
			Code int            `json:"code"`
			Data map[string]any `json:"data"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, UnsupportedProtocolVersionCode, body.Error.Code)
	require.Contains(t, body.Error.Data, "detail", "the client must be told the two declarations disagree")
}

// TestLegacyHandshakeStillWorks is the regression that matters most: adding the
// modern era must not disturb clients pinned to the handshake revisions. A
// request with no `_meta` declaration takes the legacy path and still gets a
// session.
func TestLegacyHandshakeStillWorks(t *testing.T) {
	mux := dualEraTestMux(t)

	rec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": LatestProtocolVersion,
			"clientInfo":      map[string]any{"name": "legacy-client"},
		},
	}, nil)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, LatestProtocolVersion, rec.Header().Get("MCP-Protocol-Version"))
	require.NotEmpty(t, rec.Header().Get("MCP-Session-Id"), "legacy clients still get a session")
}

// TestMalformedMetaFallsBackToLegacy keeps the era signal conservative. A params
// blob that is not a modern declaration — no `_meta`, a non-string version, an
// empty one — must not be treated as modern on a guess.
func TestMalformedMetaFallsBackToLegacy(t *testing.T) {
	for name, params := range map[string]json.RawMessage{
		"no params":        nil,
		"no meta":          json.RawMessage(`{"name":"audit"}`),
		"meta not object":  json.RawMessage(`{"_meta":"nope"}`),
		"version not text": json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":42}}`),
		"version empty":    json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"  "}}`),
	} {
		t.Run(name, func(t *testing.T) {
			_, declared := modernProtocolVersionFromParams(params)
			require.False(t, declared, "this must not be read as a modern declaration")
		})
	}
}
