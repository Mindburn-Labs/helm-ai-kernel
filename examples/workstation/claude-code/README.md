# Claude Code Workstation Adapter Wrapper

This wrapper captures a local Claude Code-style run without using undocumented
Claude Code internals. It records a manifest-first artifact directory, hashes
validation output, reads git diff summary metadata, and emits a signed Agent Run
Receipt.

```bash
HELM_BIN=go\ run\ ./core/cmd/helm-ai-kernel \
  examples/workstation/claude-code/run-capture.sh \
  "Review governance receipts" \
  "go test ./core/pkg/workstation"
```

The `hooks/` examples show how pre-network, pre-memory, pre-MCP, and post-run
steps can call the selected-effect wrapper. They are examples only; use the
documented hook surface for the local Claude Code installation.

The wrapper and hooks do not read secrets, browser sessions, or raw chat history.
