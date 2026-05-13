# Competitive Bakeoff Harness

This directory holds clean-room fixtures for comparing agent gateways, MCP wrappers, policy engines, and sandbox runners against HELM-defined execution-boundary behavior.

Do not store competitor code, copied tests, proprietary schemas, account-gated outputs, or distinctive UI/text here. Only keep:

- toy MCP servers and manifests created for HELM;
- neutral allow/deny/drift/outage vectors;
- CLI/API observations from tools that were lawfully installed and run locally;
- source, license, and access notes for each observation.

Scratch installs and logs belong outside the repository, for example:

```sh
/tmp/helm-competitive-re-2026-05-05
```

Core matrix:

```sh
helm-ai-kernel mcp scan --manifest tools/competitive-bakeoff/fixtures/hostile_mcp_manifest.json --json
helm-ai-kernel conform negative --json
helm-ai-kernel sandbox inspect --runtime wazero --json
```
