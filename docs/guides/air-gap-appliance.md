---
title: Run HELM On A Sealed Or Air-Gapped Host
last_reviewed: 2026-07-21
---

<!-- quantum_posture: this page references Ed25519 receipt signatures and signed bundles but does not implement cryptographic controls. -->

# Run HELM On A Sealed Or Air-Gapped Host

HELM AI Kernel runs as a single static binary that makes no outbound calls of
its own. That makes it a fit for a **sealed host** — an appliance or server
where every agent and inference request is routed through one boundary — and
for an **air-gapped host** with no route to the public internet.

This guide covers what the kernel does on such a host, how to place it as the
only governed path, and how a reviewer checks the record with no network.

## What HELM does here — and what the host owns

HELM decides *authority* and produces *evidence*. It does not isolate processes
or partition GPUs; the host operating system owns that.

| Layer | Owner |
| --- | --- |
| Process and resource isolation (containers, cgroups, seccomp, GPU) | Host OS |
| Network enforcement (host firewall, deny-all egress) | Host OS, using HELM's egress policy as the source |
| Action and inference governance (verdict, permit, receipt) | HELM |

> "Quarantine" in HELM is a governance state — a tool or MCP server is visible
> to policy but cannot execute until its schema and scopes are approved. It is
> not process isolation.

## The binary is offline by default

- No license check and no phone-home. The only outbound calls the binary makes
  are ones you configure (a proxy upstream) or explicitly opt into (`verify
  --online`, OTLP export).
- Built with `CGO_ENABLED=0` for `linux/amd64` and `linux/arm64` (and macOS),
  on a distroless base, with reproducible builds and an SBOM.

## Govern the local model server

Point the on-host agent at HELM instead of at the model server. Any
OpenAI-compatible server — Ollama, vLLM, llama.cpp, LM Studio, and others —
works with a base-URL swap:

```bash
helm-ai-kernel proxy \
  --upstream http://127.0.0.1:8000/v1 \
  --port 9090 \
  --sign "$HELM_SIGNING_SEED" \
  --receipts-dir /var/lib/helm/receipts
export OPENAI_BASE_URL=http://127.0.0.1:9090/v1
```

Every tool call is checked against policy and allowed, denied, or escalated;
each decision writes a hash-chained receipt. The Local Inference Gateway can
additionally pin the engine by model hash, so a receipt records *which* model
answered. See [Use The OpenAI-Compatible Proxy](use-openai-compatible-proxy.md).

## Make the egress policy the host firewall source

HELM's egress policy fails closed: an empty allowlist denies every destination.
Author the allowlist once and let the host translate it into firewall rules —
for example an nftables default-drop ruleset. On a sealed host the intended
shape is that the only reachable outbound path is the HELM gateway.

## First boot: autonomous setup, explicit authority

On first boot the kernel can inventory the host and draft a **default-deny**
policy, then wait. Activation requires a human-signed `ORG_GENESIS_APPROVAL`
over a hash-bound summary — the kernel sets itself up but cannot grant itself
authority. A blast-radius check must show the drafted policy blocks the
negative cases before it goes live.

## Verify the record with no network

Receipts and EvidencePacks verify offline first. On the sealed host — or on a
separate reviewer machine that never touched the kernel — export a pack and
check it:

```bash
helm-ai-kernel verify evidence-pack.tar
```

`verify` runs its offline checks (Ed25519 signatures, the SHA-256 hash chain,
and the JCS canonical form) before any network step; the `--online` ledger
check is opt-in and off by default. Replay from genesis works without a route
to the internet. For the full export-and-check walkthrough see
[Export And Verify EvidencePacks](export-verify-evidencepacks.md).

## Run it as a system service

A hardened reference unit ships at `deploy/systemd/helm-gateway.service`. It
runs the gateway under a restricted account with a read-only filesystem, no new
privileges, and a narrowed address-family and device set — the host enforces
the isolation, HELM produces the evidence.

## The honest boundary

"Air-gapped" here means *disconnected between maintenance windows*, not magic.
Policy-pack and binary updates reach a disconnected host as a signed bundle that
the operator applies on-site; the kernel checks the identity and integrity of
what it loads, not the intent of a model's weights. Reference policy packs —
including the HIPAA reference policy pack — are governance starting points that
you review and bind to your own obligations; they do not replace your own audit.

## Source Truth

- `core/cmd/helm-ai-kernel/proxy_cmd.go` — the governed proxy
- `core/pkg/llm/gateway/` — the Local Inference Gateway and engine pin
- `core/pkg/firewall/egress.go` — fail-closed egress policy
- `core/cmd/helm-ai-kernel/autoconfigure_cmd.go` — first-boot inventory and default-deny draft
- `core/cmd/helm-ai-kernel/verify_cmd.go` — offline pack verification
- `deploy/systemd/helm-gateway.service` — the reference system unit
