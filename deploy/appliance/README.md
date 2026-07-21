# Sealed-Boundary Appliance Reference Deployment

Reference systemd units and compiled-artifact examples for running the HELM
AI Kernel gateway on a sealed (air-gapped or egress-restricted) Linux
appliance under a **Boundary Enforcement Profile**.

Doctrine invariant: **HELM never executes isolation.** `helm-ai-kernel
boundary profile compile` compiles OS enforcement artifacts (systemd
hardening drop-ins, a default-drop nftables ruleset, cgroup limits, device
permits) from a hash-bound policy input and seals a signed compile receipt;
systemd and nftables enforce them; `boundary profile attest` proves the live
posture matches and **fails closed on drift**. Full guide:
[docs/deployment/air-gap-appliance.md](../../docs/deployment/air-gap-appliance.md).

## Files

| File | Role |
| --- | --- |
| `helm-gateway.service` | Unprivileged gateway unit. Hard-`Requires=` a successful attestation before start. |
| `helm-boundary-attest.service` | Short-lived privileged oneshot (`CAP_NET_ADMIN`, needed for `nft list`) that runs `boundary profile attest --enforce`. Non-zero exit blocks gateway start — the OS does the refusing. |
| `helm-boundary-attest.timer` | Optional periodic re-attestation. Emits MATCH/DRIFT receipts; does **not** stop a running gateway (start-time gating is the enforced path). |
| `examples/profile_input.example.json` | A complete `boundary_profile_input.v1` document (the golden-vector input from `reference_packs/boundary-profile-v1/`). |
| `examples/orchestrator.service.d/50-helm-boundary.conf` | Compiled sealed-topology drop-in for a workload unit (byte-identical to the golden-vector artifact). |
| `examples/helm-boundary.nft` | Compiled default-drop egress ruleset (byte-identical to the golden-vector artifact). |

## Quickstart

```bash
# 1. On a workstation: compile the profile from your policy input.
export HELM_SIGNING_KEY_HEX=<64-hex Ed25519 seed>   # receipts are never unsigned
helm-ai-kernel boundary profile compile \
  --input profile_input.json --out ./profile

# 2. Transfer ./profile to the appliance (e.g. inside a signed update bundle),
#    then install:
sudo mkdir -p /etc/helm/boundary
sudo cp -r profile/. /etc/helm/boundary/artifacts/
sudo cp profile/compile_receipt.json /etc/helm/boundary/
sudo cp profile/systemd/*/50-helm-boundary.conf ... # into /etc/systemd/system/<unit>.d/
sudo nft -f profile/nftables/helm-boundary.nft
sudo cp helm-gateway.service helm-boundary-attest.service /etc/systemd/system/
sudo systemctl daemon-reload

# 3. Start: attestation gates the gateway.
sudo systemctl enable --now helm-gateway.service
# On DRIFT or probe failure the attest oneshot exits non-zero and the
# gateway does not start.

# 4. Anyone can verify offline (no network, no server):
helm-ai-kernel boundary profile verify \
  --receipt /etc/helm/boundary/compile_receipt.json \
  --artifacts /etc/helm/boundary/artifacts \
  --public-key <trust-root hex>
```

## Honest boundary

- HELM compiles and attests; **systemd/nftables enforce**. No eBPF, seccomp,
  TPM, hardware-enclave, or packet-blocking enforcement claim is made by this
  repository.
- Drift is caught at gateway (re)start, timer ticks, and on-demand attest
  runs — **not continuously**.
- Domain-name egress rules (`allowed_domains`) are enforced by the gateway's
  L7 egress checker, not by nftables (L3/L4); the compiled ruleset covers
  CIDRs and known protocol ports only, and the profile input requires an
  explicit acknowledgment when domains are allowed without CIDRs.
- The offline update-bundle surface is a **format + verifier** only
  (`boundary profile bundle-verify`); there is no build tooling or OTA
  mechanism in this repo.
