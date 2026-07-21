# Design — Sealed-Boundary Appliance Profile (Boundary Enforcement Profile)

> **Status:** Accepted, implemented as HELM-305 Slice A targeting the 0.7.4
> milestone. Graduated from the original engagement proposal
> (`Mindburn-Labs/docs/gtm/partners/2026-07-20-harsh-micro-dc-appliance/`)
> with the as-built corrections in §6. Sequencing decision on record
> (HELM-305): §6 option 1 — build now — chosen by the DRI on 2026-07-20.
> Release cut and VERSION bump remain a separate, DRI-only gate.

## 1. Problem

On a sealed appliance, HELM's governance covers what routes through HELM. The
gaps named by the field: OS-kernel-level isolation (no nftables/systemd
hardening/cgroup emission existed), GPU governance, reference systemd units,
and an air-gap deployment guide — all without breaking the doctrine that the
OS does the isolation while HELM governs authority and produces proof, and
without collapsing "quarantine" (a governance state, `core/pkg/mcp`) into
process isolation.

## 2. Doctrine invariant

> **HELM never *executes* isolation. HELM *compiles* enforcement artifacts
> from policy, the appliance OS *executes* them, and HELM *attests* that the
> OS applied them — failing closed on divergence.**

The gaps map onto three verbs HELM already owns — compile, attest,
fail-closed — never the fourth (enforce):

| Gap | What HELM must NOT become | What shipped instead |
|---|---|---|
| OS-kernel isolation | the firewall / LSM / cgroup manager | compiler for systemd hardening drop-ins + default-drop nftables ruleset + cgroup limits; posture attestor; fail-closed start gate |
| GPU governance | a GPU/MIG partition manager | `DeviceAllow=` device permits + `DevicePolicy=closed` (attestation binding to `EnginePin.AttestedMeasurement` is Slice B) |
| systemd units | an init system / supervisor | reference units under `deploy/appliance/` (privileged attest oneshot + unprivileged gateway) |
| air-gap guide | an OTA/update daemon | `docs/deployment/air-gap-appliance.md` + signed offline update-bundle **format + verifier** (`update_bundle_manifest.v1`); build tooling out of scope |

## 3. Architecture (as built)

Subsystem: `core/pkg/boundary/profile` (+ `profile/updatebundle`) — new
subpackages of the existing `boundary` package tree; protected packages
(`guardian`, `crypto`, `kernel`, `proofgraph`, `evidencepack`, `contracts`)
are consumed through public APIs only and were not modified. Nothing runs in
the kernel verdict path.

```
 ProfileInput (boundary_profile_input.v1, hash-bound)
        │  Compile (deterministic; double-compile byte-identical)
        ▼
 artifacts: systemd drop-ins · helm-boundary.nft · cgroup limits ·
            posture/expected_posture.json
        +  CompileReceipt (profile_compile_receipt.v1: JCS + SHA-256 +
           Ed25519 over policy_input_hash → artifact refs → artifact_set_hash
           → mode tier → kernel version)
        │
   OS applies (systemctl / nft -f)          Attest (prober seam: systemctl
        │                                   show · nft list · cgroup fs)
        ▼                                        │
 live posture ───────────────────────────────────┤
                                    MATCH ───────┴────── DRIFT / probe error
                                      │                     │
                            gateway may start      attest --enforce exits
                            (systemd Requires=)    non-zero → systemd refuses
                                                   to start the gateway;
                                                   DRIFT emits a sealed
                                                   posture_attestation.v1
```

Key mechanics:

- **Records** (`CompileReceipt`, `PostureAttestation`, `UpdateBundleManifest`)
  mirror the modern `contracts.LaunchProviderCertificationRecord` signing
  pattern: signing bytes = JCS of the record with `record_hash`/`signature`
  cleared; `record_hash` = `sha256:`-prefixed; `signature` =
  `ed25519:`-prefixed; offline verification. They live in `boundary/profile`
  (not protected `contracts/`), with schema-parity tests binding the Go
  structs — including the operator input and its embedded
  `firewall.EgressPolicy` / `sandbox.ResourceLimits` shapes — to the four
  schemas under `protocols/json-schemas/boundary/`.
- **Artifact set hash**: path-sorted `{path, sha256}` refs, hashed as JCS —
  independently re-derivable from the artifact directory.
- **Attestor seam**: three injectable provider funcs (systemd props, nft
  ruleset, cgroup limits) mirroring `launchpad/runtime`'s
  `DockerInfoProvider` pattern; `LiveProber()` compiles everywhere, probes
  only on a systemd/nftables host, and every probe failure is fail-closed
  (never a fabricated MATCH). nftables comparison hashes normalized text; the
  ruleset is emitted with the named `priority filter` so file and `nft list`
  renderings normalize identically. Resource limits are attested through the
  cgroup-v2 filesystem (raw integers) to avoid systemd's humanized rendering.
- **Fail-closed gate**: `GateDispatch(att)` = hash-sealed MATCH, else closed.
  No server-side call site in Slice A — the enforced path is the systemd
  dependency (`helm-boundary-attest.service`, a short-lived
  `CAP_NET_ADMIN` oneshot, gates the fully unprivileged gateway unit).
  Putting the gate into gateway dispatch is a documented future integration,
  deliberately kept out of the verdict path.
- **CLI**: `boundary profile compile|attest|verify|bundle-verify`, nested
  under the existing `boundary` command (top-level `boundary verify` and
  `bundle` were taken). Signing reuses the `HELM_SIGNING_KEY_HEX` convention;
  compile refuses to emit unsigned receipts.
- **Conformance**: golden vector packs `reference_packs/boundary-profile-v1`
  and `reference_packs/update-bundle-v1` with independent pure-Python
  re-verification and negative vectors (incl. `drift_reported_as_match`),
  wired into `make verify-fixtures`.

## 4. Doctrine safety checks (held in code)

- No privileged isolation code in the verdict path; `mcp.ShouldDispatch` and
  all guardian surfaces untouched (structural: no import edges between
  `boundary/profile*` and `guardian`/`kernel`/`mcp`).
- "Quarantine" ≠ "Boundary Enforcement Profile" — no `Quarantine*`
  identifiers in the new packages; docs use "quarantine" only for the
  governance state.
- Wire formats vendor-neutral: check `target`/`property` values are free-form
  strings; no systemd name enums in `posture_attestation.v1`.
- No compliance claim from compiled profiles; CLAIMS.md red line preserved
  (no eBPF/seccomp/TPM/hardware-enclave/packet-blocking enforcement claim).
- OSS/commercial line: compiler + attestor + verifiers are OSS local-first
  boundary surfaces; fleet management and hosted control-plane stay
  commercial.

## 5. Slice B (0.8+, explicitly not in 0.7.4)

seccomp profile emission per mode tier; GPU attestation binding
(`EnginePin.AttestedMeasurement` → CC-attestation/TPM quote); update-bundle
**build tooling**; measured-boot posture; server-side `GateDispatch` wiring
(bound by the `GateDispatch` doc contract: deserialized attestations must be
signature-verified against a trust root before gating — a hash seal is
integrity, not authenticity).

## 6. As-built corrections vs the original proposal

1. `core/pkg/boundary/` already existed (perimeter/approval-ceremony/
   extauthz) → new code is the `profile/` subpackage family.
2. CLI `boundary verify` and top-level `bundle` were taken → verbs nest as
   `boundary profile …`.
3. Signed-input wording corrected: no canonical **signed policy-bundle record
   contract usable as compiler input** exists; existing bundles are
   content-hash-verified, and `policy/reconcile.Ed25519PolicyVerifier`
   verifies reconciler bundle signatures — the future signed-input slot binds
   to that pattern. The Slice A input is hash-bound (`policy_input_hash`).
4. No repo-wide mode-ladder enum exists; tiers (`observe|enforce`) validate
   locally to the package.
5. Compile-time DNS resolution dropped: domains stay L7 gateway scope, with a
   mandatory `egress_domains_gateway_only` acknowledgment when domains are
   allowed without CIDRs (no silent L7/L3 contradiction).
6. The nft probe needs `CAP_NET_ADMIN` → attestation runs in a dedicated
   privileged oneshot unit the gateway `Requires=`, instead of an
   `ExecCondition=` inside the unprivileged gateway (which would either
   over-privilege the gateway or brick startup).
7. Drift-window honesty made explicit: attestation gates at (re)start, timer
   ticks, and on-demand runs — not continuously.
