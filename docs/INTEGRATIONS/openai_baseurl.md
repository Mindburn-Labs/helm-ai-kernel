# OpenAI-Compatible Proxy Integration

Start the proxy:

```bash
helm serve --policy ./release.high_risk.v3.toml
./bin/helm proxy --upstream https://api.openai.com/v1
```

Then update the client base URL to `http://localhost:8080/v1`.

The proxy command is retained for existing OpenAI-compatible clients. Receipts emitted through the local boundary are available from:

```bash
helm receipts tail --agent agent.titan.exec --server http://127.0.0.1:7714
```

Python example:

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8080/v1")
```

TypeScript example:

```ts
const baseUrl = "http://localhost:8080/v1";
```

See the retained examples under `examples/python_openai_baseurl/`, `examples/js_openai_baseurl/`, and `examples/ts_openai_baseurl/`.
