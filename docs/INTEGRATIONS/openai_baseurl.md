# OpenAI-Compatible Proxy Integration

The OpenAI-compatible proxy is the retained OSS path for apps that already use OpenAI-style clients. It keeps the client library stable and moves the execution boundary to HELM.

## Start The Boundary

```bash
helm serve --policy ./release.high_risk.v3.toml
./bin/helm proxy --upstream https://api.openai.com/v1
```

Then update client base URL to `http://localhost:8080/v1`.

## Python

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8080/v1")
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Return the policy status."}],
)
print(response.choices[0].message.content)
```

## TypeScript

```ts
import OpenAI from "openai";

const openai = new OpenAI({
  baseURL: "http://localhost:8080/v1",
});

const response = await openai.chat.completions.create({
  model: "gpt-4",
  messages: [{ role: "user", content: "Return the policy status." }],
});
console.log(response.choices[0]?.message?.content);
```

## Receipt Behavior

Allowed responses should be tied to a HELM decision and receipt path. In local development, tail receipts with:

```bash
helm receipts tail --agent agent.titan.exec --server http://127.0.0.1:7714
```

Use the integration only when you can prove both outcomes:

- an allowed request returns normal model output and receipt metadata;
- a disallowed tool or effect returns a denial reason instead of silently executing.

## Failure Modes

| Symptom | Cause | Fix |
| --- | --- | --- |
| no receipts appear | the app still calls the upstream provider directly | log the request host and set the client base URL to HELM |
| denied request retries forever | client treats 403 as transient | do not retry definitive policy denials |
| upstream auth fails | provider key is missing from the configured boundary | configure provider auth according to your deployment model |
| receipt tail is empty | wrong agent filter or receipt server | remove the filter and verify the receipt server address |

Retained examples live under `examples/python_openai_baseurl/`, `examples/js_openai_baseurl/`, and `examples/ts_openai_baseurl/`.
