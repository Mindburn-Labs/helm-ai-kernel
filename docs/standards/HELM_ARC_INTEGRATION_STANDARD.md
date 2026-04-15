# HELM x ARC Integration Standard
Status: Draft Canonical Standard
Version: 0.1.0
Owner: Mindburn Labs / HELM Core
Scope: Internal canonical architecture and implementation standard
Last Updated: 2026-03-27

## 1. Purpose

This standard defines the canonical way ARC benchmark environments are integrated into HELM.

The purpose is to ensure that ARC support:
- fits the existing HELM architecture exactly
- reuses the deterministic truth plane rather than bypassing it
- compiles into OrgGenome / OrgPhenotype rather than creating benchmark-only runtime islands
- produces standard HELM receipts, ProofGraph nodes, and EvidencePack artifacts
- introduces zero orphaned policy, proof, storage, or execution structures
- supports both research iteration and frozen blind-eval lanes

This standard is binding for all HELM ARC-related implementation work.

## 2. Canonical architectural position

ARC is not a second runtime.
ARC is not a second proof system.
ARC is not a special benchmark exception path.
ARC is not a separate memory plane.

ARC is a governed benchmark connector family expressed through:
- Plane 2 - OrgGenome templates and policy overlays
- Plane 3 - Deterministic Kernel, CPI, PEP, Guardian
- Plane 4 - ProofGraph, receipts, EvidencePacks
- Plane 5 - Tool / connector adapter contracts
- Plane 6 - LKS / CKS knowledge integration
- Plane 7 - Mission Control / MAMA surfaces

### 2.1 Canonical mapping to HELM planes

#### Plane 1 - Identity and Trust
ARC execution is initiated by an authenticated HELM principal.
ARC bridge instances are bound to connector principals.
Model principals, if attested, remain separate from connector principals.

#### Plane 2 - OrgGenome
ARC behavior is described by:
- benchmark connector bindings
- benchmark policy profiles
- budget ceilings
- lane rules
- retention rules
- promotion rules
- environment source policies
- model pinning for frozen eval lanes

#### Plane 3 - Deterministic Kernel
Every ARC effect flows through:
- Intent creation
- CPI plan validation
- PEP execution authorization
- Guardian verdict
- bounded execution
- standard receipt generation

#### Plane 4 - ProofGraph
ARC produces:
- INTENT nodes
- ATTESTATION / KERNEL_VERDICT nodes
- EFFECT nodes
- OBSERVATION references
- CHECKPOINT nodes
- EvidencePack slices

#### Plane 5 - Tools and Connectors
ARC provider-specific logic is isolated inside a Python bridge sidecar plus a single canonical Go connector package.

#### Plane 6 - Knowledge Plane
ARC replay-derived heuristics, notes, failures, and candidate skills enter LKS first.
Only promoted benchmark facts and frozen eval configs enter CKS.

#### Plane 7 - Surfaces
ARC is surfaced through existing MAMA / Mission Control / Studio surfaces.
No separate ARC truth UI is allowed.

## 3. Design goals

The integration MUST:
- preserve deterministic execution authority
- remain HUDF-compatible
- compile through existing OrgGenome / compiler flows
- emit standard HELM receipts
- preserve replay and evidence integrity
- enforce strict separation between research and blind-eval lanes
- avoid benchmark-specific bypasses
- avoid benchmark-specific truth stores
- avoid benchmark-specific policy engines
- avoid benchmark-specific command ecosystems

## 4. Non-goals

The integration MUST NOT:
- port ARC provider logic into the HELM kernel
- fork the proof model
- fork the receipt model
- fork the policy model
- create a benchmark-only runtime state machine outside OrgPhenotype
- create a benchmark-only memory graph
- create a separate ARC frontend app with its own backend truth
- add decorative command sprawl unrelated to execution leverage

## 5. Core invariants

### 5.1 Truth-plane invariant
No ARC action may mutate benchmark state through any path other than:
`Intent -> CPI -> PEP -> Connector Effect -> Receipt -> ProofGraph`

### 5.2 No-bypass invariant
Neither MAMA, Studio, planner logic, skills, nor UI surfaces may call the ARC bridge directly.
All execution must go through the existing governed execution path.

### 5.3 No-orphan invariant
No ARC-specific structure may exist unless it is attached to one of:
- OrgGenome
- OrgPhenotype
- ProofGraph
- EvidencePack
- LKS
- CKS
- connector package root
- schema registry
- conformance harness

### 5.4 Lane isolation invariant
Research iteration and blind-eval execution must remain separable and machine-enforced.

### 5.5 Hashability invariant
All normative ARC requests, observations, receipts, and scorecard artifacts must be canonically hashable.

### 5.6 Artifact integrity invariant
Rendered visuals such as PNGs or GIFs are non-normative.
Normative state artifacts must be machine-verifiable structured payloads.

## 6. OrgGenome and OrgPhenotype integration

### 6.1 Canonical OrgGenome templates

The following template IDs are reserved:

- `orggenome.template.arc_agi3_research.v1`
- `orggenome.template.arc_agi3_blind_eval.v1`

These templates define:
- connector bindings
- mode permissions
- budget ceilings
- replay retention
- scorecard policy
- skill promotion policy
- frozen eval rules
- connector source rules
- model pinning rules where applicable

### 6.2 Canonical ARC phenotype slices

ARC runtime state must live in OrgPhenotype via the following slices:

- `benchmark_sessions`
- `active_scorecards`
- `replay_index`
- `episode_state`
- `belief_state_refs`
- `candidate_skill_queue`
- `eval_freeze_state`
- `bridge_health`
- `benchmark_budgets`

No parallel benchmark state authority is allowed outside these phenotype slices plus referenced artifacts.

## 7. Connector contract

### 7.1 Connector family

Canonical connector family ID:
`connector.arc`

Canonical implementation IDs:
- `connector.arc.bridge.local.v1`
- `connector.arc.bridge.remote.v1`

### 7.2 Supported execution kinds

- `DIGITAL`

### 7.3 Canonical action URNs

Required:
- `helm.connector.arc.capabilities.v1`
- `helm.connector.arc.env.list.v1`
- `helm.connector.arc.session.open.v1`
- `helm.connector.arc.session.step.v1`
- `helm.connector.arc.session.inspect.v1`
- `helm.connector.arc.session.close.v1`
- `helm.connector.arc.scorecard.read.v1`
- `helm.connector.arc.replay.export.v1`
- `helm.connector.arc.artifact.fetch.v1`

Optional later:
- `helm.connector.arc.swarm.run.v1`
- `helm.connector.arc.dataset.sync.v1`
- `helm.connector.arc.goldenpack.export.v1`

### 7.4 Effect and risk mapping

#### `helm.connector.arc.env.list.v1`
- effect_class: `E0`
- risk_class: `T0`

#### `helm.connector.arc.session.open.v1` local
- effect_class: `E1`
- risk_class: `T0`

#### `helm.connector.arc.session.step.v1` local
- effect_class: `E1`
- risk_class: `T0`

#### `helm.connector.arc.session.inspect.v1`
- effect_class: `E0`
- risk_class: `T0`

#### `helm.connector.arc.session.close.v1` local
- effect_class: `E1`
- risk_class: `T0`

#### `helm.connector.arc.session.open.v1` remote
- effect_class: `E2`
- risk_class: `T1`

#### `helm.connector.arc.session.step.v1` remote
- effect_class: `E2`
- risk_class: `T1`

#### `helm.connector.arc.scorecard.read.v1`
- effect_class: `E0` or `E2` depending source
- risk_class: `T1`

#### `helm.connector.arc.replay.export.v1`
- effect_class: `E0` local or `E2` remote
- risk_class: `T1`

### 7.5 Canonical effect payload

All ARC operations must use the standard HELM effect envelope.

Example:

```json
{
  "effect_type": "CONNECTOR_CALL",
  "action_urn": "helm.connector.arc.session.step.v1",
  "connector_id": "connector.arc.bridge.local.v1",
  "target_ref": "arc-session://sess_01J...",
  "args": {
    "session_id": "sess_01J...",
    "action": {
      "type": "ACTION6",
      "coordinates": [12, 7]
    },
    "step_budget": {
      "gas_limit_steps": 1,
      "time_limit_ms": 500
    }
  },
  "idempotency_key": "arc-step-sess_01J-00042",
  "executor_kind": "DIGITAL"
}
```

### 7.6 Canonical preconditions

Before any ARC effect is authorized, PEP must verify:

* principal is authenticated and authorized
* connector implementation is allowed by policy
* connector contract version is pinned or allowed
* schema hash is pinned or allowed
* lane permits the action
* session belongs to the current tenant and mission
* effect class and risk class match policy
* blind-eval freeze is not violated
* action budget remains
* environment source is allowed
* session is healthy
* requested action family is legal in the current mode

## 8. Receipt schema

### 8.1 Rule

ARC does not define a second receipt system.
ARC defines specialized receipt payloads inside the existing HELM proof model.

### 8.2 Canonical step receipt

Schema ID:
`receipts.arc.tool_receipt.v1`

```json
{
  "receipt_type": "ARC_TOOL_RECEIPT",
  "connector_id": "connector.arc.bridge.local.v1",
  "bridge_mode": "LOCAL",
  "session_id": "sess_01J...",
  "scorecard_id": null,
  "env_id": "ls20",
  "episode_id": "ep_01J...",
  "step_index": 42,
  "action_hash": "sha256:...",
  "observation_hash": "sha256:...",
  "available_actions_hash": "sha256:...",
  "session_state_hash": "sha256:...",
  "request_hash": "sha256:...",
  "response_hash": "sha256:...",
  "artifact_refs": [
    "artifact://arc/episodes/ep_01J/obs/00042.json"
  ],
  "status": "ok",
  "reason_code": "OK",
  "latency_ms": 37,
  "budget": {
    "gas_limit_steps": 1,
    "gas_used_steps": 1,
    "time_limit_ms": 500,
    "time_used_ms": 37
  }
}
```

### 8.3 Canonical scorecard receipt

Schema ID:
`receipts.arc.scorecard_receipt.v1`

```json
{
  "receipt_type": "ARC_SCORECARD_RECEIPT",
  "connector_id": "connector.arc.bridge.remote.v1",
  "bridge_mode": "ONLINE",
  "scorecard_id": "sc_01J...",
  "lane": "arc-blind-eval",
  "suite_id": "arc-agi3-official-shadow-v1",
  "scorecard_hash": "sha256:...",
  "artifact_refs": [
    "artifact://arc/scorecards/sc_01J/scorecard.json"
  ],
  "status": "ok",
  "reason_code": "OK"
}
```

### 8.4 Required hashes

All step receipts must include:

* `action_hash`
* `observation_hash`
* `available_actions_hash`
* `session_state_hash`
* `request_hash`
* `response_hash`

### 8.5 Observation artifact rule

Normative observation artifacts must be structured and canonical.

Required fields:

* `session_id`
* `episode_id`
* `step_index`
* `frames`
* `terminated`
* `truncated`
* `available_actions`
* `observation_hash`
* `previous_observation_hash`
* `timestamp_logical`

Rendered PNGs or GIFs may exist as convenience artifacts only.

### 8.6 ProofGraph node chain

For each ARC step, the canonical chain is:

1. `INTENT`
2. `ATTESTATION(type=KERNEL_VERDICT)`
3. `EFFECT(connector_receipt=ARC_TOOL_RECEIPT)`
4. optional `OBSERVATION` fact promotion
5. periodic or terminal `CHECKPOINT`

### 8.7 Condensation rule

ARC local research traffic may be condensed.
Blind-eval traffic may not silently lose reconstructability.

Condensation policy:

* local research runs may condense step traces every N steps or at end-of-episode
* online research runs may condense only if scorecard-linked trace integrity is preserved
* blind-eval runs must preserve dispute-grade step reconstructability

## 9. EvidencePack integration

### 9.1 Canonical pack ID format

`epack.arc.<mission>.<episode>.<lamport-range>.v1`

### 9.2 Canonical contents

Each ARC EvidencePack slice may contain:

* `MANIFEST.json`
* `proofgraph/nodes/*.json`
* `connector/request.json`
* `connector/response.json`
* `session/open.json`
* `session/close.json`
* `observations/000001.json`
* `observations/000042.json`
* `receipts/arc_tool_receipt.json`
* `receipts/arc_scorecard_receipt.json`
* `replay/replay_ref.json`
* `policy/effective_policy.json`
* `genome/org_genome_ref.json`
* `phenotype/checkpoint_ref.json`

### 9.3 Artifact storage rule

All raw benchmark artifacts must live in the standard HELM artifact store.
ProofGraph nodes reference them by stable hash and artifact URI.
No separate benchmark blob truth store is allowed.

## 10. Knowledge Plane integration

### 10.1 LKS usage

The following ARC outputs belong in LKS:

* replay summaries
* hypotheses
* failure clusters
* tactic notes
* candidate skills
* planner observations
* environment notes
* operator annotations

These may influence future proposals but do not gain execution authority automatically.

### 10.2 CKS usage

The following ARC outputs may enter CKS only after promotion:

* frozen benchmark suite manifests
* approved benchmark metadata
* approved scorecard summaries if needed for policy
* approved skill versions
* approved blind-eval configs
* approved connector compatibility facts

### 10.3 No benchmark memory fork

No standalone ARC memory system may exist outside:

* LKS
* CKS
* artifacts referenced by those stores

## 11. Policy profiles

### 11.1 Canonical profiles

* `profile.arc-research-local.v1`
* `profile.arc-research-online.v1`
* `profile.arc-blind-eval.v1`

### 11.2 `profile.arc-research-local.v1`

Purpose:

* heavy offline iteration
* replay mining
* candidate skill synthesis
* local environment stepping
* fast experiments

#### P0 ceilings

* `MAX_PARALLEL_ARC_SESSIONS`
* `MAX_ARC_ACTIONS_PER_EPISODE`
* `MAX_ARC_ACTIONS_PER_HOUR`
* `MAX_ARC_REPLAY_EXPORTS_PER_HOUR`
* `MAX_ARC_SKILL_PROMOTIONS_PER_DAY`
* `MAX_ARC_ARTIFACT_BYTES_PER_EPISODE`

#### P1 rules

Allow:

* `env.list`
* `session.open`
* `session.step`
* `session.inspect`
* `session.close`
* `replay.export`

Disallow by default:

* official remote blind eval
* suite freeze bypass
* online score submission if policy does not permit it

Allow:

* LKS updates
* candidate skill synthesis
* local planner mutation

### 11.3 `profile.arc-research-online.v1`

Purpose:

* interact with remote official services
* retrieve remote scorecards
* run controlled online experiments

Adds:

* capped remote request budgets
* scorecard-read permission
* stricter artifact retention
* mandatory session-to-scorecard linkage where applicable

### 11.4 `profile.arc-blind-eval.v1`

Purpose:

* frozen evaluation lane
* honest comparison
* no contamination

Hard rules:

* no skill synthesis during active suite
* no planner mutation during active suite
* no prompt mutation during active suite
* no policy mutation during active suite
* no model changes during active suite
* no new CKS promotions affecting active suite
* scorecard linkage required
* replay export required
* suite manifest required
* run manifest hash required
* all action attempts receipted

### 11.5 Approval rules

Operator approval is required for:

* entering blind-eval lane
* changing pinned model in blind-eval lane
* enabling official remote lane if disabled by default
* promoting any skill into blind-eval allowlist
* switching connector implementation in frozen suites

### 11.6 Budget fields

Required ARC budget fields:

* `max_planner_nodes_per_decision`
* `max_subagents_per_episode`
* `max_replay_analysis_seconds`
* `max_remote_eval_requests_per_hour`
* `max_artifact_bytes_per_episode`
* `max_scorecard_reads_per_hour`

## 12. Bridge API

### 12.1 Rule

Provider-specific ARC logic must be isolated in a Python sidecar bridge.
The bridge has zero governance authority.
The bridge has zero policy authority.
The bridge has zero proof authority.

### 12.2 Transport

Primary transport:

* Unix domain socket HTTP+JSON
* named pipe equivalent on Windows

Fallback dev transport:

* localhost HTTP

### 12.3 Canonical endpoints

Required:

* `POST /v1/capabilities`
* `POST /v1/env/list`
* `POST /v1/session/open`
* `POST /v1/session/step`
* `POST /v1/session/inspect`
* `POST /v1/session/close`
* `POST /v1/scorecard/read`
* `POST /v1/replay/export`

### 12.4 Shared request envelope

```json
{
  "contract_version": "arc-bridge.v1",
  "request_id": "req_01J...",
  "idempotency_key": "idem_01J...",
  "tenant_id": "tenant_01J...",
  "mission_id": "mission_01J...",
  "principal_id": "principal_01J...",
  "policy_hash": "sha256:...",
  "schema_hash": "sha256:...",
  "payload": {}
}
```

### 12.5 Shared response envelope

```json
{
  "contract_version": "arc-bridge.v1",
  "request_id": "req_01J...",
  "status": "ok",
  "reason_code": "OK",
  "schema_hash": "sha256:...",
  "payload": {},
  "bridge_receipt_hash": "sha256:..."
}
```

### 12.6 Example: open session

Request:

```json
{
  "payload": {
    "mode": "LOCAL",
    "env_id": "ls20",
    "render_mode": "none",
    "scorecard_mode": "NONE"
  }
}
```

Response:

```json
{
  "payload": {
    "session_id": "sess_01J...",
    "env_id": "ls20",
    "available_actions": ["ACTION1", "ACTION2", "ACTION6"],
    "session_state_hash": "sha256:..."
  }
}
```

### 12.7 Example: step session

Request:

```json
{
  "payload": {
    "session_id": "sess_01J...",
    "action": {
      "type": "ACTION6",
      "coordinates": [12, 7]
    }
  }
}
```

Response:

```json
{
  "payload": {
    "session_id": "sess_01J...",
    "step_index": 42,
    "observation": {
      "frames": [[[0, 1, 1], [0, 2, 2]]],
      "terminated": false,
      "truncated": false
    },
    "available_actions": ["ACTION1", "ACTION6", "ACTION7"],
    "session_state_hash": "sha256:..."
  }
}
```

### 12.8 Drift controls

The bridge must expose:

* `contract_version`
* `schema_hash`
* `provider_version`
* `bridge_build_hash`

PEP must deny if drift exceeds policy.

## 13. MAMA / Mission Control surface mapping

ARC should map into the core MAMA command surface rather than create a giant parallel namespace.

Canonical mappings:

* `/env` -> environment selection, bridge health, session open/close
* `/episode` -> episode lifecycle
* `/bench` -> benchmark suite execution
* `/replay` -> replay inspection
* `/proof` -> proof chain and EvidencePack
* `/promote` -> skill / profile promotion
* `/mode` -> lane and execution mode transitions
* `/permissions` -> connector and lane permissions

ARC-specific command growth should be resisted unless a function cannot fit the canonical control plane.

## 14. File plan

### Phase 0 - contracts and schemas

#### [NEW]

* `docs/standards/HELM_ARC_INTEGRATION_STANDARD.md`
* `schemas/connectors/arc/arc_bridge_request.schema.json`
* `schemas/connectors/arc/arc_bridge_response.schema.json`
* `schemas/connectors/arc/arc_session_open.schema.json`
* `schemas/connectors/arc/arc_session_step.schema.json`
* `schemas/receipts/arc_tool_receipt.schema.json`
* `schemas/receipts/arc_scorecard_receipt.schema.json`
* `schemas/policies/arc_profile.schema.json`

#### [MODIFY]

* `schemas/effects/effect_type_catalog.schema.json`
* `schemas/reason_codes/*.json` or canonical reason registry

Definition of done:

* all schemas versioned
* all schemas hashable
* no runtime code yet
* no duplicate schema roots elsewhere

### Phase 1 - Go connector root

#### [NEW]

* `core/pkg/connectors/arc/`
* `core/pkg/connectors/arc/client.go`
* `core/pkg/connectors/arc/contracts.go`
* `core/pkg/connectors/arc/mapper.go`
* `core/pkg/connectors/arc/policy.go`
* `core/pkg/connectors/arc/errors.go`
* `core/pkg/receipts/arc.go`

#### [MODIFY]

* existing generic contract, guardian, and intent wiring packages only

Rule:

* no duplicate ARC connector packages elsewhere

Definition of done:

* one canonical ARC connector root
* all calls go through generic effect path

### Phase 2 - policy and genome

#### [NEW]

* `core/pkg/orgdna/templates/arc_agi3_research/`
* `core/pkg/orgdna/templates/arc_agi3_blind_eval/`
* `core/pkg/policy/profiles/arc/research_local.yaml`
* `core/pkg/policy/profiles/arc/research_online.yaml`
* `core/pkg/policy/profiles/arc/blind_eval.yaml`

#### [MODIFY]

* existing compiler / genome / phenotype / runtime packages only

Rule:

* no standalone benchmark config system

Definition of done:

* ARC compiles through existing OrgGenome machinery
* phenotype slices are canonical

### Phase 3 - Python bridge

#### [NEW]

* `research/arc_bridge/`
* `research/arc_bridge/app.py`
* `research/arc_bridge/contracts.py`
* `research/arc_bridge/session_store.py`
* `research/arc_bridge/scorecards.py`
* `research/arc_bridge/replays.py`
* `research/arc_bridge/health.py`
* `research/arc_bridge/pyproject.toml`

Rule:

* provider logic only
* no governance logic
* no proof logic
* no policy logic

Definition of done:

* bridge can open, step, inspect, close, export replay, read scorecards
* Go client speaks canonical schemas

### Phase 4 - proof and artifacts

#### [NEW]

* `core/pkg/artifacts/arc/`
* `core/pkg/artifacts/arc/observations.go`
* `core/pkg/artifacts/arc/replays.go`
* `core/pkg/evidence/arc/pack_builder.go`

#### [MODIFY]

* existing provenance, evidence, artifact, and proof packages only

Rule:

* no separate benchmark blob truth store

Definition of done:

* all ARC artifacts are hash-addressed and evidence-compatible
* ProofGraph references them by stable URI

### Phase 5 - MAMA runtime integration

#### [MODIFY]

* existing mission / agent / runtime / context packages only

#### [NEW]

* only if a canonical MAMA root already exists:

  * `core/pkg/experimental/mama/lanes/arc.go`

Rule:

* if `experimental/mama/` is not yet canonical, do not create it just for ARC
* lane logic must live in the existing mission control runtime location

Definition of done:

* ARC is controllable through canonical MAMA surfaces
* no ARC runtime bypasses

### Phase 6 - UI surfaces

#### [MODIFY]

* existing Studio / Mission Control UI only

#### [NEW]

* ARC session inspector
* replay timeline view
* scorecard view
* proof linkage view

Rule:

* no standalone ARC app
* no standalone benchmark backend
* no duplicate UI truth state

Definition of done:

* UI reads canonical truth sources only

### Phase 7 - conformance

#### [NEW]

* `tests/conformance/arc/`
* `tests/conformance/arc/contract_hash_test.go`
* `tests/conformance/arc/replay_determinism_test.go`
* `tests/conformance/arc/policy_freeze_test.go`
* `tests/conformance/arc/condensation_test.go`
* `tests/conformance/arc/blind_eval_guard_test.go`
* `artifacts/golden/arc/`

Definition of done:

* ARC extension is certifiable and regression-tested

## 15. Forbidden orphaned structures

The following are forbidden and must not be introduced:

* `apps/arc-ui/`
* `core/pkg/arc_runtime/` as a second runtime
* `core/pkg/arc_proof/` as a second proof system
* `core/pkg/arc_policy/` as a second policy engine
* `mama/arc_memory/` if it bypasses LKS / CKS
* `benchmark_db` as a parallel truth store
* direct UI -> bridge calls
* direct planner -> bridge calls
* direct skill -> bridge calls

## 16. Verification matrix

ARC integration is complete only if all of the following are true.

### 16.1 Architectural verification

* ARC is expressed as connector + policy profile + genome template
* ARC introduces no kernel fork
* ARC introduces no second proof plane
* ARC introduces no second policy plane
* ARC introduces no second memory plane

### 16.2 Execution verification

* every ARC action emits standard HELM intent and verdict flow
* every action has a canonical receipt
* blind-eval freeze is enforceable
* connector drift causes fail-closed denial

### 16.3 Artifact verification

* observations are stored canonically
* replay references are stable
* EvidencePack contents are deterministic
* rendered artifacts are non-normative only

### 16.4 Lane verification

* research and blind-eval lanes are isolated
* skills cannot self-promote into blind-eval without policy approval
* planner / prompt / model mutation during blind-eval is blocked

### 16.5 UI verification

* Studio / Mission Control consumes canonical truth only
* no duplicate benchmark state authority exists in the frontend

## 17. Final decision

The canonical HELM position is:

ARC inside HELM is a governed benchmark connector family compiled into OrgGenome, executed through the deterministic truth plane, recorded in ProofGraph, retained in EvidencePacks, and surfaced through Mission Control.

Any implementation that deviates from this and creates benchmark-only authority, policy, memory, proof, or execution paths is non-compliant with this standard.
