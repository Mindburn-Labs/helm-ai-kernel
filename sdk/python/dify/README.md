# helm-dify

HELM governance adapter for the [Dify](https://dify.ai) platform.

## What it does

Governs Dify platform tool and workflow calls through HELM via HTTP middleware:

1. Intercepts requests to governed paths (chat-messages, workflows) for HELM evaluation
2. Denied calls return 403 with reason code (fail-closed by default)
3. Receipts with SHA-256 hashes are collected for every approved execution

## Quick start

```python
from helm_dify import HelmDifyGovernor, HelmDifyMiddleware
from flask import Flask

governor = HelmDifyGovernor(helm_url="http://localhost:8080")
app = Flask(__name__)
app.wsgi_app = HelmDifyMiddleware(app.wsgi_app, governor)
```

## Configuration

| Parameter          | Default                 | Description          |
| ------------------ | ----------------------- | -------------------- |
| `helm_url`         | `http://localhost:8080` | HELM kernel URL      |
| `api_key`          | `None`                  | HELM API key         |
| `fail_closed`      | `True`                  | Deny on HELM errors  |
| `collect_receipts` | `True`                  | Keep receipt chain   |
| `timeout`          | `30.0`                  | HTTP timeout seconds |
| `governed_paths`   | `["/v1/chat-messages", "/v1/workflows/run"]` | Paths to intercept |

## License

Apache-2.0
