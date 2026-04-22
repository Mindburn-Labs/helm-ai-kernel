# OpenAI-Compatible Proxy Integration

Start the proxy:

```bash
./bin/helm proxy --upstream https://api.openai.com/v1
```

Then update the client base URL to `http://localhost:8080/v1`.

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
