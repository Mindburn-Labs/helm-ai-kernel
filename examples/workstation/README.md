# Workstation Adapter Examples

These examples package the manifest-first workstation adapter for local Codex or Claude Code-style runs.

They do not use private vendor APIs. The wrapper records a local artifact directory, then HELM imports that directory into a signed Agent Run Receipt and deterministic ProofGraph.

They do not install or exercise the native-client lifecycle. A wrapper receipt
is not proof that Codex or Claude Code loaded HELM configuration; use
[`docs/INTEGRATIONS/native-client-lifecycle.md`](../../docs/INTEGRATIONS/native-client-lifecycle.md)
for the project-scoped setup and sterile-session review boundary.

## Codex-style run

See `codex/README.md` for the local wrapper boundary.

```bash
HELM_BIN=go\ run\ ./core/cmd/helm-ai-kernel \
  examples/workstation/codex/run-capture.sh \
  "Update workstation docs" \
  "go test ./core/pkg/workstation"
```

## Claude Code-style run

See `claude-code/README.md` for the local wrapper and hook examples.

```bash
HELM_BIN=go\ run\ ./core/cmd/helm-ai-kernel \
  examples/workstation/claude-code/run-capture.sh \
  "Review governance receipts" \
  "go test ./core/pkg/workstation"
```

## Selected effect wrapper

```bash
helm-ai-kernel workstation capture wrap \
  --class network \
  --target https://forbidden.example \
  --receipt-dir /tmp/helm-workstation-decisions
```

`capture wrap` writes a signed policy decision receipt. If the decision is `DENY`, the wrapper exits `126` and does not run the wrapped command.
