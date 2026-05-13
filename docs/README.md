# HELM AI Kernel Docs

This tree is the canonical public documentation source for HELM AI Kernel. Public protocol, schema, SDK, conformance, verification, deployment, and Console material starts here before it is mirrored to the docs site.

## Start

- [Documentation index](index.md)
- [Quickstart](QUICKSTART.md)
- [Developer journey](DEVELOPER_JOURNEY.md)
- [Architecture](ARCHITECTURE.md)
- [Canonical diagrams](architecture/canonical-diagrams.md)

## How-To

- [Conformance](CONFORMANCE.md)
- [Verification](VERIFICATION.md)
- [Publishing](PUBLISHING.md)
- [Troubleshooting](TROUBLESHOOTING.md)

## Reference

- [Compatibility](COMPATIBILITY.md)
- [Execution security model](EXECUTION_SECURITY_MODEL.md)
- [SDK index](sdks/00_INDEX.md)
- [CLI reference](reference/cli.md)
- [HTTP API reference](reference/http-api.md)
- [OpenAPI contract](../api/openapi/README.md)

## Explanation

- [Kernel scope](KERNEL_SCOPE.md)
- [OWASP MCP threat mapping](OWASP_MCP_THREAT_MAPPING.md)
- [Architecture rationale: cognitive firewall](architecture/cognitive-firewall.md)
- [Canonical visual doctrine](architecture/canonical-diagrams.md)

## Security And Compliance

- [Prompt-injection watchlist](security/prompt-injection-watchlist-2026-04.md)
- [EU AI Act high-risk pack](compliance/eu-ai-act-high-risk-pack.md)

## Documentation Gates

- `make docs-coverage`
- `make docs-truth`

Update [documentation-coverage.csv](documentation-coverage.csv) whenever an active source surface, protocol, schema, SDK, public manifest entry, or docs ownership boundary changes.
