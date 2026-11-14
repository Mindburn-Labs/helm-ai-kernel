<!-- quantum_posture: this walkthrough verifies classical Ed25519 receipts and makes no post-quantum claim. -->

# Local HTTP first use

From the current source checkout, use Go 1.26.11 and Python 3.10 or newer:

```bash
make first-use
```

With mise, use `mise exec -- make first-use` after `mise trust` and
`mise install`. `make build` produces `bin/helm-ai-kernel`, the `bin/helm`
alias and `bin/receipt_verify`.

The walkthrough starts a task-owned server on unused loopback ports with a
fresh HOME, new SQLite state, a generated credential and the public
`agent_tool_call_boundary.toml` sample policy. It ignores existing HELM,
database, proxy and provider configuration. It then checks:

1. The benign request without credentials is refused with HTTP 401.
2. The same request with the wrong tenant is refused with HTTP 403.
3. Authenticated `read-ticket` returns `ALLOW`; `dangerous-shell` returns `DENY`.
4. Each fetched `receipt.v5` has the corresponding receipt ID, decision ID,
   signed decision hash, effect and verdict.
5. After the server exits, the standalone verifier accepts both receipts
   against `root.pub` exported from this server's data directory.
6. Changing the allowed verdict to `DENY`, or supplying another Ed25519 public
   key, makes the verifier fail with exit 1.

This is a local policy evaluation and receipt journey. It dispatches no tools
and calls no provider. It does not establish production deployment or receipt
trust beyond the local signer whose public key you exported.

The script prints `PASS` only after all checks run successfully. It stops its
server on failure as well, returns a nonzero exit code, and retains the log and
results for inspection. The evidence directory includes `run.json` with binary
and policy hashes, `serve.log`, decision responses, receipts, verifier outputs
and `result.json`.

To choose a new output directory after building:

```bash
python3 examples/first-use/run.py --out /tmp/helm-first-use
```

An existing output directory is refused to preserve previous evidence. Without
`--out`, the script creates a fresh temporary directory and prints its path.
The directory is private and includes local keys; share only the intended
public receipts and `root.pub`, then remove the directory when no longer needed.

Repeat offline verification using the printed directory:

```bash
./bin/receipt_verify --receipt /tmp/helm-first-use/allow.receipt.json \
  --key-file /tmp/helm-first-use/root.pub --json
./bin/receipt_verify --receipt /tmp/helm-first-use/deny.receipt.json \
  --key-file /tmp/helm-first-use/root.pub --json
```

Supply the public key from a source you trust. A key bundled by an unknown
signer with its receipt is not a trust root. For a server you can keep calling,
see [Developer Journey](../../docs/DEVELOPER_JOURNEY.md#local-boundary).
