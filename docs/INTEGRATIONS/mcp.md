# MCP Integration

HELM retains an MCP surface for governed tool access.

The local boundary quickstart remains the entry point:

```bash
helm serve --policy ./release.high_risk.v3.toml
```

## Run the Server

```bash
./bin/helm mcp serve
```

## OAuth Resource and Scope Enforcement

`./bin/helm mcp serve --auth oauth` supports production JWKS validation and the dev-only `HELM_OAUTH_BEARER_TOKEN` fallback. Production mode validates issuer, audience, expiration, issued-at, configured global scopes, and the MCP resource indicator before forwarding the request to the gateway.

Configure production OAuth with:

| Variable | Purpose |
| --- | --- |
| `HELM_OAUTH_JWKS_URL` | JWKS endpoint used to verify bearer-token signatures |
| `HELM_OAUTH_ISSUER` | Required `iss` claim |
| `HELM_OAUTH_AUDIENCE` | Required `aud` claim |
| `HELM_OAUTH_RESOURCE` | Required RFC 8707 resource indicator; defaults to `<base-url>/mcp` |
| `HELM_OAUTH_SCOPES` | Comma- or space-separated scopes required before gateway entry |

Tool definitions may also declare `required_scopes`. These are surfaced to MCP clients as `requiredScopes` in `tools/list` and are enforced again at execution time for both `/mcp/v1/execute` and JSON-RPC `tools/call`. A missing per-tool scope returns `MCP.OAUTH.INSUFFICIENT_SCOPE` on the REST surface or a JSON-RPC application error on the streamable MCP surface.

The resource check follows [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707): the MCP gateway treats the token audience plus `resource` / `resources` token members as accepted resource indicators and rejects tokens that are not minted for this MCP endpoint.

## Build a Bundle

```bash
./bin/helm mcp pack --client claude-desktop --out helm.mcpb
```

## Install a Local Client Configuration

```bash
./bin/helm mcp install --client claude-code
```

Use `./bin/helm mcp print-config --client <name>` for text configuration snippets where supported by the CLI.

MCP activity that emits receipts can be inspected with:

```bash
helm receipts tail --agent agent.titan.exec
```
