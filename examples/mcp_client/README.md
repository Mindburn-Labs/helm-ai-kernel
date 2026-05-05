# MCP Client Example

Shows HELM's MCP (Model Context Protocol) gateway integration.

## Prerequisites

- HELM running at `http://localhost:8080` (`docker compose up -d`)
- `curl` and `jq`

## Run

```bash
cd examples/mcp_client
bash main.sh
```

## Expected Output

The script prints the MCP capabilities response, a governed tool execution
response, and an OpenAI-compatible chat response. If the HELM server is not
running, the script prints `(server not running)` for each request.
