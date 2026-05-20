# Codex Workstation Adapter Wrapper

This wrapper captures a local Codex-style run without using private Codex APIs.
It records a manifest-first artifact directory, hashes validation output, reads
git diff summary metadata, and emits a signed Agent Run Receipt.

```bash
HELM_BIN=go\ run\ ./core/cmd/helm-ai-kernel \
  examples/workstation/codex/run-capture.sh \
  "Update workstation docs" \
  "go test ./core/pkg/workstation"
```

The wrapper does not read secrets, browser sessions, or raw chat history.
