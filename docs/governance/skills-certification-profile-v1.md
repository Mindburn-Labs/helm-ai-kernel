# Skills Certification Profile v1 (R8)

**Status:** preview specification; lint tool merged at
`tools/skills-cert-profile/lint_skill.py`.
**Origin:** Step AOS ships production Skills in the OpenClaw `SKILL.md`
format (see `stepfun-ai/StepAudio-Skills`). That format has trigger routing
and environment requirements but **no risk, effect, or receipt metadata**.
This profile is the HELM certification layer on top of the same grammar.

## Baseline (OpenClaw-compatible, required)

| Field | Requirement |
| --- | --- |
| `name` | Matches directory name; kebab-case |
| `description` | Trigger phrases plus explicit do-NOT-use boundaries and sibling-skill disambiguation |
| `version` | Semver |
| `metadata.<runtime>.requires.bins` / `.env` | Declared binary and env dependencies |
| `metadata.<runtime>.primaryEnv` | Single primary credential env var, referenced by name only |

## HELM certification additions (required for the HELM certified mark)

All under `metadata.helm`:

| Field | Values | Purpose |
| --- | --- | --- |
| `effect_class` | per `capability_manifest.v1` enum | Worst-case effect the skill can produce |
| `reversibility` | `none` / `compensating_action` / `exact_undo` | Drives rollback-plan requirement |
| `data_boundary` | `local_only` / `device_boundary` / `org_boundary` / `external` | Where skill data may flow; network skills must not claim `local_only` |
| `permissions` | list of capability_ids the skill needs granted | Feeds token minting at task start |
| `receipts.required` | `true` | Every effect dispatched by the skill must produce receipts |
| `memory_access` | `{user_domain, agent_domain, cross_domain_read}` | Per memory-governance.md |

Certification rule: a skill whose scripts perform network egress, credential
use, or writes must declare the matching `effect_class`; the lint tool
cross-checks declared `requires.bins`/`env` against declared effects
(e.g. `curl` + `primaryEnv` present but `effect_class: read_only` → fail).

## Pipeline

```text
SKILL.md (OpenClaw grammar)
  → lint_skill.py (structural + consistency checks)
  → capability manifest generation (one per dispatched capability)
  → connector-cert review → certified manifest registered
  → conformance replay (incl. adversarial-policy-v1 vectors where applicable)
```

## Lint tool

```bash
python3 tools/skills-cert-profile/lint_skill.py <SKILL.md> [...]
```

Exit 0 = structurally valid **and** HELM-certified fields complete.
Exit 1 with per-field report otherwise. Baseline-valid but
uncertified skills report exactly which `metadata.helm` fields are missing.
