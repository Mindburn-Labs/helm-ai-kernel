# Boundary Enforcement Profile — Sealed-Appliance Deployment

How to run the HELM AI Kernel gateway on a sealed Linux appliance —
air-gapped or egress-restricted — with OS-level enforcement **compiled from
policy** and *provable* on demand (not continuously *monitored*; see the
honesty section).

> **Relationship to the sealed-host baseline:** [Run HELM On A Sealed Or
> Air-Gapped Host](../guides/air-gap-appliance.md) covers placing the current
> kernel release as the only governed path on a sealed host (single hardened
> unit under `deploy/systemd/`, local-inference governance, offline
> verification). **This document layers the Boundary Enforcement Profile on
> top**: compiled systemd/nftables/cgroup artifacts, signed compile receipts,
> live posture attestation, and fail-closed drift gating via the
> `deploy/appliance/` unit pair. The profile ships with the 0.7.4 milestone.

Doctrine invariant, stated once and relied on everywhere:

> **HELM never executes isolation. HELM compiles enforcement artifacts from
> policy, hands them to the OS (systemd, nftables, cgroup v2) to execute, and
> attests that the OS applied them — failing closed on divergence.**

"Quarantine" remains a governance state over MCP tools/servers
(`core/pkg/mcp`); the OS containment described here is always called the
**Boundary Enforcement Profile**. The two are deliberately never collapsed.

## 1. Sealed topology

```
                 ┌─────────────────────────── appliance ───────────────────────────┐
                 │                                                                  │
   policy input  │  systemd drop-ins        helm-gateway.service (unprivileged)     │
   (hash-bound)  │  ┌─────────────────┐     ┌───────────────────────────────┐       │
 ──compile──────►│  │ orchestrator.d/ │     │ HELM gateway: verdicts,       │──┐    │
   + signed      │  │ 50-helm-…conf   ├────►│ receipts, L7 egress checker   │  │    │
   compile       │  │ IPAddressDeny=  │     └───────────────▲───────────────┘  │    │
   receipt       │  │ any + gateway   │                     │ Requires=        │    │
                 │  │ only            │     helm-boundary-attest.service       │    │
                 │  └─────────────────┘     (oneshot, CAP_NET_ADMIN,           │    │
                 │        workloads         attest --enforce, fail closed)     │    │
                 │                                                             │    │
                 │  nftables table inet helm_boundary: output policy drop ◄────┘    │
                 │  (lo + established + compiled CIDR/port allows only)             │
                 └──────────────────────────────────────────────────────────────────┘
```

- Every workload unit gets a compiled drop-in that makes the HELM gateway its
  **only** reachable endpoint (`IPAddressDeny=any` + `IPAddressAllow=<gateway
  IP>` for TCP, or `PrivateNetwork=yes` + the gateway socket via
  `ReadWritePaths=` for unix sockets).
- Host egress is default-drop: the compiled `helm_boundary` nftables table
  allows loopback, established flows, and the profile's CIDR/known-protocol
  ports — nothing else. An **empty allowlist compiles to pure default-drop**,
  the same fail-closed semantics the gateway's `EgressChecker` enforces at L7.
- If anyone loosens an OS rule to open a side channel, the next posture
  attestation reports DRIFT and the gateway refuses to (re)start.

## 2. Compile → apply → attest lifecycle

### Compile (workstation, connected side)

```bash
export HELM_SIGNING_KEY_HEX=<64-hex Ed25519 seed>   # compile receipts are never unsigned
helm-ai-kernel boundary profile compile --input profile_input.json --out ./profile
```

Input contract: `boundary_profile_input.v1`
(`protocols/json-schemas/boundary/boundary_profile_input.v1.schema.json`; a
complete example lives at `deploy/appliance/examples/profile_input.example.json`).
The document embeds the gateway/workload topology, `firewall.EgressPolicy`,
`sandbox.ResourceLimits`, systemd hardening options, and device permits, and
is **hash-bound** into the compile receipt (`policy_input_hash`).

Signed-input status, stated precisely: no canonical *signed policy-bundle
record contract* exists yet as a compiler input in this repository — existing
bundle types are content-hash-verified, and `policy/reconcile`'s
`Ed25519PolicyVerifier` verifies reconciler bundle signatures. When a signed
input envelope lands, its verification slots in ahead of `Compile`, binding
to that verifier pattern, without changing the receipt format.

The compiler emits, deterministically (double-compile is byte-identical):

| Artifact | Enforced by |
| --- | --- |
| `systemd/<gateway>.d/50-helm-boundary.conf` | systemd (hardening + `CPUQuota=`/`MemoryMax=`/`TasksMax=`/`DeviceAllow=`) |
| `systemd/<workload>.d/50-helm-boundary.conf` | systemd (sealed topology) |
| `nftables/helm-boundary.nft` | nftables (default-drop egress) |
| `posture/expected_posture.json` | nobody — it is the attestor's expectation set |
| `compile_receipt.json` | — the JCS+Ed25519 proof object binding all of the above |

### Apply (appliance, the OS's job)

Install the drop-ins under `/etc/systemd/system/<unit>.d/`, load the ruleset
with `nft -f`, `systemctl daemon-reload`. HELM ships no installer daemon —
applying enforcement is deliberately an OS operation an operator (or their
config management) performs.

### Attest (appliance, fail-closed gate)

`deploy/appliance/helm-boundary-attest.service` runs

```bash
helm-ai-kernel boundary profile attest --enforce \
  --receipt /etc/helm/boundary/compile_receipt.json \
  --artifacts /etc/helm/boundary/artifacts
```

which (1) hard-errors if the on-disk artifacts no longer hash to the
receipt's `artifact_set_hash` (tamper is not "drift"), (2) probes live
posture — `systemctl show` properties, `nft list table inet helm_boundary`
(compared as a hash of normalized text), cgroup-v2 limits (raw integers,
immune to systemd's humanized rendering) — and (3) writes a hash-sealed
`posture_attestation.v1` receipt with verdict `MATCH` or `DRIFT` where every
failed check carries `{expected, observed}`. **DRIFT and probe errors exit
non-zero**; `helm-gateway.service` hard-`Requires=` this oneshot, so systemd
refuses to start the gateway. The OS does the refusing.

**Privilege model:** reading the live nftables ruleset requires
`CAP_NET_ADMIN`. That capability lives only in the short-lived attest oneshot
(`CapabilityBoundingSet=CAP_NET_ADMIN`), never in the long-running gateway,
which stays fully unprivileged (`CapabilityBoundingSet=` empty). Running the
probe inside the gateway would either over-privilege it or turn fail-closed
into fail-bricked.

**Unit lineage:** `deploy/systemd/helm-gateway.service` is the standalone
hardened single-host reference (no profile gating). The `deploy/appliance/`
pair is the profile-gated topology: same hardening posture, plus the
attest-oneshot dependency and the compiled per-profile drop-in.

## 3. First boot, governance side

The boundary profile seals the box; governance still starts explicitly:

```bash
helm-ai-kernel onboard                      # store + keys + config
helm-ai-kernel autoconfigure scan           # deterministic agent-surface inventory
helm-ai-kernel autoconfigure draft-policy   # default-deny policy draft
helm-ai-kernel autoconfigure simulate       # blast-radius preview
helm-ai-kernel autoconfigure activate --mode constrained --sign
```

"Autonomous setup, explicit authority": nothing dispatches until activation,
and the boundary profile is orthogonal — it constrains the *host*, while
verdicts constrain *actions*.

## 4. Offline verification (the auditor's path)

Everything verifies with no network and no running server:

```bash
# Compile receipt + artifact set + attestation, offline:
helm-ai-kernel boundary profile verify \
  --receipt compile_receipt.json --artifacts ./artifacts \
  --attestation latest.json --public-key <trust-root hex>

# Update bundles (see §5):
helm-ai-kernel boundary profile bundle-verify \
  --bundle updates.tar.gz --manifest manifest.json --public-key <publisher hex>
```

Cross-runtime parity is pinned by golden vectors: independent pure-Python
verifiers re-derive every hash, signature, and binding — including negative
vectors such as `drift_reported_as_match` — under
`reference_packs/boundary-profile-v1/` and `reference_packs/update-bundle-v1/`
(`make verify-boundary-profile-vectors verify-update-bundle-vectors`, both
part of `make verify-fixtures`).

## 5. Offline update bundles (format + verifier only)

Disconnected fleets receive policy packs and kernel artifacts as a tar.gz
plus a signed `update_bundle_manifest.v1` (JCS + SHA-256 + Ed25519).
`bundle-verify` streams the archive once and rejects extra, missing,
mismatched, oversized, path-traversal, and non-regular-file members.

Honest scope: **this repository ships the format and the verifier, not build
tooling and not an OTA mechanism.** Operators may additionally sign the
manifest file with `cosign sign-blob` at the transport layer; the in-repo
trust anchor is the Ed25519 signature and nothing here imports cosign.

## 6. Honest boundary (read before quoting any capability)

- **Who enforces:** systemd and nftables. This repo makes **no eBPF, seccomp,
  TPM, hardware-enclave, or packet-blocking enforcement claim** (CLAIMS.md
  red line). Systemd's `IPAddressDeny=` may use BPF internally — that is
  systemd's implementation, not a HELM capability claim.
- **Drift window:** posture is attested at gateway (re)start, on
  `helm-boundary-attest.timer` ticks, and on demand. It is **not** monitored
  continuously. A timer-detected DRIFT emits a sealed receipt (drift is
  evidence) but does not stop an already-running gateway unless the operator
  wires `OnFailure=` themselves.
- **Domains vs CIDRs:** `allowed_domains` cannot become nftables rules (nft
  is L3/L4). Domains are enforced by the gateway's L7 `EgressChecker` only;
  the compiler refuses a policy that allows domains with no CIDRs unless the
  operator sets `egress_domains_gateway_only: true` — an explicit
  acknowledgment, never a silent contradiction.
- **"Disconnected" means between maintenance windows**, not magic: update
  bundles cross the gap on operator-controlled media.
- **In-process gate:** the exported `profile.GateDispatch(attestation)`
  predicate (hash-sealed MATCH or closed) has **no server-side call site in
  this release** — wiring it into gateway dispatch is a documented future
  integration, kept out of the verdict path by design. The enforced path
  today is the systemd unit dependency described in §2.
- Mode tiers are `observe | enforce`, validated locally to the boundary
  profile package; they are not a repo-wide autonomy ladder.
- quantum_posture: every record in this lifecycle (compile receipt, posture
  attestation, update-bundle manifest) uses classical Ed25519 signatures; no
  hybrid or post-quantum claim.
