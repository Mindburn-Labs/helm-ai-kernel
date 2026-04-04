# Skill Bundle Standard

**Version:** 1.0.0
**Status:** DRAFT
**Owner:** Mindburn Labs / HELM Core
**Last Updated:** 2026-04-04

---

## Abstract

This standard defines the canonical structure, lifecycle, validation rules, and
security requirements for HELM Skill Bundles. A Skill Bundle is the unit of
governed capability distribution inside the HELM runtime: a versioned, signed,
content-addressed package that declares exactly what an agent is permitted to do,
under which policy profile, and within which sandbox constraints.

Skill Bundles are the distribution format for agent capabilities. They are
installed into the HELM runtime through the Forge mutation authority (see
ADR-004), which enforces promotion through a staged certification ladder before
any bundle reaches production. An agent that attempts to execute a capability not
declared in its active Skill Bundle MUST be denied by the fail-closed Guardian.

---

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

| Term | Definition |
|---|---|
| **Skill Bundle** | A versioned, signed package of governed agent capability. |
| **SkillManifest** | The canonical metadata document embedded in every bundle. |
| **Forge** | The only valid mutation authority for skill creation and promotion (ADR-004). |
| **Self-Modification Class (C0-C3)** | Certification level of a bundle: C0=sandbox, C1=shadow, C2=canary, C3=production. |
| **Sandbox Profile** | Named runtime isolation configuration (see CAPABILITY_MANIFESTS). |
| **Policy Profile** | A named policy binding reference that governs effect authorization. |
| **Artifact Manifest** | Per-standard artifact metadata linked from a bundle (see artifact-manifest-v1). |
| **SBOM** | Software Bill of Materials — dependency manifest for supply-chain auditing. |
| **Bundle Hash** | SHA-256 of the canonical (JCS-serialized) bundle archive. |
| **Signature Ref** | Reference to the Ed25519 signature covering `bundle_hash`. |
| **ProofGraph** | Immutable causal graph of intents, decisions, and effects (HELM core). |

---

## Wire Format

### SkillManifest

The `SkillManifest` is a JSON document embedded at `manifest.json` in the root
of every Skill Bundle archive. All fields are required unless marked OPTIONAL.

```json
{
  "schema": "https://helm.mindburn.org/schemas/skills/skill_manifest.v1.json",
  "id": "skills/org.example.research-assistant",
  "name": "Research Assistant",
  "version": "2.3.1",
  "description": "Searches the web and summarizes findings into LKS entries.",
  "entry_point": "src/index.js",
  "state": "candidate",
  "self_mod_class": "C0",
  "risk_class": "R1",
  "sandbox_profile": "network-restricted",
  "capabilities": [
    "network.outbound",
    "memory.read.lks",
    "memory.promote",
    "artifact.write"
  ],
  "compatibility": {
    "runtime_spec_version": "^1.0",
    "min_kernel_version": "0.9.0",
    "max_kernel_version": null,
    "required_packs": [],
    "required_connectors": ["connectors/org.example.search-api"]
  },
  "inputs": [
    {
      "name": "query",
      "schema_ref": "schemas/research/query.v1.json",
      "trust_class": "verified",
      "required": true,
      "sensitive": false
    }
  ],
  "outputs": [
    {
      "name": "summary_artifact",
      "schema_ref": "schemas/research/summary.v1.json",
      "trust_class": "lks",
      "promotable": true,
      "sensitive": false
    }
  ],
  "policy_profile_ref": "policy-profiles/standard-read-write.yaml",
  "artifact_manifest_ref": "artifacts/manifest.json",
  "sbom_ref": "sbom.json",
  "bundle_hash": "sha256:a3f2c1...",
  "signature_ref": "signatures/bundle.sig"
}
```

### Field Descriptions

| Field | Type | Constraints | Description |
|---|---|---|---|
| `schema` | string (URI) | REQUIRED | JSON Schema `$id` for this manifest version. |
| `id` | string | REQUIRED, format `skills/{reverse-domain}.{name}` | Globally unique, stable skill identifier. |
| `name` | string | REQUIRED, 1–128 chars | Human-readable display name. |
| `version` | string | REQUIRED, semver | Version of this skill release. |
| `description` | string | REQUIRED, 1–512 chars | One-sentence capability description. |
| `entry_point` | string | REQUIRED | Relative path to the skill's main module within the bundle. |
| `state` | SkillBundleState | REQUIRED | Current lifecycle state (see State Machine). |
| `self_mod_class` | string | REQUIRED, enum C0/C1/C2/C3 | Certification level. MUST match Forge promotion record. |
| `risk_class` | string | REQUIRED, enum R0/R1/R2/R3 | Action risk class per ADR-005. |
| `sandbox_profile` | string | REQUIRED | Named sandbox profile reference. |
| `capabilities` | SkillCapability[] | REQUIRED | Exhaustive list of permitted capabilities. Empty = read-only. |
| `compatibility` | object | REQUIRED | Runtime and connector compatibility constraints. |
| `inputs` | InputDecl[] | OPTIONAL | Declared input parameters. |
| `outputs` | OutputDecl[] | OPTIONAL | Declared output artifacts. |
| `policy_profile_ref` | string | REQUIRED | Path to governing policy profile inside bundle. |
| `artifact_manifest_ref` | string | OPTIONAL | Path to artifact manifest (artifact-manifest-v1). |
| `sbom_ref` | string | OPTIONAL | Path to SBOM file for supply-chain auditing. |
| `bundle_hash` | string | REQUIRED, format `sha256:{hex}` | SHA-256 of canonical bundle archive. |
| `signature_ref` | string | REQUIRED | Path to Ed25519 signature over `bundle_hash`. |

### SkillBundleState

```
candidate  →  certified  →  deprecated
                 ↓
              revoked
```

| State | Meaning |
|---|---|
| `candidate` | Submitted for review; MUST NOT execute in production. |
| `certified` | Passed conformance; MAY execute per `self_mod_class` level. |
| `deprecated` | Superseded; existing deployments MAY continue; no new installs. |
| `revoked` | Withdrawn due to security or policy violation; MUST NOT execute anywhere. |

### SkillCapability Enum

| Value | Description |
|---|---|
| `files.read` | Read access to the filesystem sandbox. |
| `files.write` | Write access to the filesystem sandbox. |
| `sandbox.exec` | Execute subprocesses inside the sandbox. |
| `network.outbound` | Outbound network requests via Effects Gateway. |
| `channel.send` | Send messages via a declared channel connector. |
| `memory.read.lks` | Read from Local Knowledge Store. |
| `memory.read.cks` | Read from Certified Knowledge Store. |
| `memory.promote` | Submit a promotion claim (knowledge-promotion-v1). |
| `approval.request` | Trigger a human approval ceremony. |
| `artifact.write` | Write to content-addressed artifact storage (artifact-manifest-v1). |
| `connector.invoke` | Invoke a registered connector via Effects Gateway. |

### InputDecl

| Field | Type | Description |
|---|---|---|
| `name` | string | Parameter name. |
| `schema_ref` | string | JSON Schema reference. |
| `trust_class` | string | Minimum trust class required on the input. |
| `required` | bool | Whether input MUST be present at invocation. |
| `sensitive` | bool | Whether value is redacted in audit logs. |

### OutputDecl

| Field | Type | Description |
|---|---|---|
| `name` | string | Output name. |
| `schema_ref` | string | JSON Schema reference. |
| `trust_class` | string | Trust class assigned to the output artifact. |
| `promotable` | bool | Whether output MAY be submitted for LKS→CKS promotion. |
| `sensitive` | bool | Whether value is redacted in audit logs. |

---

## Validation Rules

1. **MUST** — `bundle_hash` MUST be verified against the archive before any
   installation step proceeds. Any mismatch MUST abort installation.

2. **MUST** — The Ed25519 signature at `signature_ref` MUST verify against the
   HELM trust root public key for the publishing principal. An invalid signature
   MUST abort installation.

3. **MUST** — `self_mod_class` MUST match the Forge promotion record for this
   bundle ID and version. Discrepancies MUST be treated as a revocation event.

4. **MUST** — A bundle in `revoked` state MUST NOT be installed or executed.
   Kernels MUST check state on every execution attempt, not just at install time.

5. **MUST** — `capabilities` MUST be the exhaustive set. The runtime MUST deny
   any capability request not present in the declared list, even if the policy
   profile would otherwise permit it.

6. **MUST** — `risk_class` MUST be consistent with the most permissive
   `capabilities` entry (e.g., `network.outbound` implies at minimum R1).

7. **SHOULD** — `sbom_ref` SHOULD be present for all bundles at `C2` or higher.

8. **MUST NOT** — A bundle MUST NOT declare `connector.invoke` without naming the
   target connector in `compatibility.required_connectors`.

9. **SHOULD** — Bundles with `promotable: true` outputs SHOULD declare an
   `artifact_manifest_ref` linking output schemas to artifact-manifest-v1.

10. **MUST** — Bundles MUST embed a `policy_profile_ref`. A missing or
    unresolvable policy profile MUST be treated as fail-closed (deny all).

---

## State Machine

```
[Forge submit]
      │
      ▼
 candidate ──(C0 tests pass + manager review)──▶ C1 shadow
      │                                               │
 (rejected)                               (C1 canary tests pass)
      │                                               ▼
   revoked ◀──(security violation)────────── C2 canary
                                                      │
                                           (canary KPIs pass + approval)
                                                      ▼
                                               certified (C3)
                                                      │
                                            (superseded by new version)
                                                      ▼
                                               deprecated
                                                      │
                                              (violation found)
                                                      ▼
                                                revoked
```

Promotion from `candidate→C1` and `C2→C3` MUST produce an approval receipt
signed by an authorized HELM manager principal. These receipts MUST be recorded
in the ProofGraph before the state transition is committed.

---

## Versioning Policy

- Skill Bundle versions follow semantic versioning (semver 2.0).
- A new **major** version (1.x → 2.x) MUST be treated as a new skill identity;
  the old `id` MUST be deprecated before the new version reaches `certified`.
- A new **minor** version MAY add capabilities; existing deployments MUST be
  migrated within 90 days.
- A new **patch** version MUST NOT add or remove capabilities.
- Published `certified` bundles are immutable. Corrections require a new semver.

---

## Security Considerations

- **Supply-chain integrity.** The `bundle_hash` + `signature_ref` pair provides
  end-to-end tamper detection from the publisher to the install target. All
  verification steps are deterministic and logged in the ProofGraph.

- **Capability minimalism.** The `capabilities` list is the first line of
  defense. Reviewers MUST reject bundles that declare capabilities beyond what
  the skill's purpose requires.

- **Forge as mutation choke-point.** No skill enters production without passing
  through the Forge promotion ladder. Direct file-system installation or
  runtime injection bypasses all governance and MUST be structurally impossible.

- **Revocation propagation.** Revoked bundle IDs MUST be distributed to all
  HELM nodes within the tenant within the SLA defined by the deployment's
  `policy.revocation_propagation_sla_ms`. Kernels that cannot confirm revocation
  status MUST deny execution (fail-closed).

---

## References

- ADR-001: HELM Is Execution Authority, Not Assistant Shell
- ADR-004: All Runtime Mutation Goes Through Forge
- ADR-005: R0-R3 Action Risk Class Taxonomy
- ADR-006: Schema Namespace Organization
- MAMA AI Canonical Standard (MAMA_AI_CANONICAL_STANDARD.md)
- artifact-manifest-v1.md (this standard set)
- knowledge-promotion-v1.md (this standard set)
- connector-release-v1.md (this standard set)
- CAPABILITY_MANIFESTS.md
- EXECUTION_SECURITY_MODEL.md
