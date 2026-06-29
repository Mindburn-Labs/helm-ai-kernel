---
title: Use The OpenAI-Compatible Proxy
last_reviewed: 2026-06-29
---

# Use The OpenAI-Compatible Proxy

Keep an OpenAI-shaped client interface while HELM makes the boundary decision
and emits receipts.

## 1. Start HELM

```bash
helm-ai-kernel serve --policy ./release.high_risk.v3.toml
```

## 2. Start The Proxy

```bash
python3 scripts/launch/mock-openai-upstream.py --port 19090
helm-ai-kernel proxy \
  --upstream http://127.0.0.1:19090/v1 \
  --port 9090 \
  --receipts-dir ./helm-receipts
```

## 3. Point The Client At HELM

```bash
export OPENAI_BASE_URL=http://127.0.0.1:9090/v1
export OPENAI_API_KEY=local-dev-key
```

## 4. Verify Denial

```bash
./scripts/launch/demo-openai-proxy.sh
```

Expected denial responses include `X-Helm-Status: DENIED` and
`X-Helm-Receipt-ID`.

## Source Truth

- `core/cmd/helm-ai-kernel/proxy_cmd.go`
- `scripts/launch/demo-openai-proxy.sh`
- `scripts/launch/mock-openai-upstream.py`
- `docs/INTEGRATIONS/openai_baseurl.md`
