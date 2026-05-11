# JavaScript — OpenAI base_url Example

Shows HELM integration with native fetch (no SDK dependency).

## Prerequisites

- HELM running at `http://port 3000` (`docker compose up -d`)
- Node.js 18+

## Run

```bash
cd examples/js_openai_baseurl
node main.js
```

## Expected Output

The script prints the response content, model, and response id returned by the
HELM boundary. Policy denials are returned as the boundary's JSON error body.
