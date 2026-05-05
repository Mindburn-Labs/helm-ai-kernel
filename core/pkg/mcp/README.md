# HELM OSS MCP Package Source Owner

## Audience

Use this file when changing MCP gateway behavior, tool catalogs, trust checks, OAuth context, argument scanning, quarantine, rug-pull detection, or session handling.

## Responsibility

`core/pkg/mcp` owns the in-process MCP trust and gateway model used by the CLI/runtime and public MCP integration docs. Public docs can show setup and examples; this package owns protocol handling and safety decisions.

## Public Status

Classification: `public-direct`.

Public docs should link here from:

- `helm-oss/integrations/mcp`
- `helm-oss/reference/execution-boundary`
- `helm-oss/reference/http-api`
- `helm-oss/security/owasp-agentic-top10-mapping`
- `helm-oss/owasp-mcp-threat-mapping`

## Source Map

- Gateway and protocol: `gateway.go`, `protocol.go`, `server.go`, `session.go`.
- Catalog and docs scanning: `catalog.go`, `docscan.go`.
- Argument and execution safety: `argscan.go`, `firewall.go`, `quarantine.go`.
- Trust and auth context: `trust.go`, `jwks.go`, `oauth_context.go`, `delegation_scope_test.go`.
- Supply-chain risk checks: `rugpull.go`, `typosquat.go`, `mcptox_test.go`.

## Documentation Rules

- Public MCP examples must state whether they exercise local CLI MCP behavior, HTTP gateway behavior, or docs-platform `/mcp` discovery behavior.
- Do not claim a third-party MCP threat class is mitigated unless the matching scanner/firewall/test exists.
- Tool catalog and trust output changes require public integration and troubleshooting updates.

## Validation

Run:

```bash
cd core
go test ./pkg/mcp -count=1
cd ..
make docs-coverage docs-truth
```
