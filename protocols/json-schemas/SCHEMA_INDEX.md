# HELM JSON Schema Index

> Normative index of all JSON schemas under `protocols/json-schemas/`.
> Schemas are classified by domain, conformance level, and status.

## Conformance Levels

| Level             | Meaning                                        |
| ----------------- | ---------------------------------------------- |
| **L1**            | Core — required for any HELM implementation    |
| **L2**            | Extended — required for production deployments |
| **L3**            | Optional — supplementary functionality         |
| **Informational** | Reference — not required for conformance       |

## Index

### Core (`core/`)

| Schema                            | Conformance | Status    | Description                               |
| --------------------------------- | ----------- | --------- | ----------------------------------------- |
| `ProvenanceEnvelope.v1.json`      | L1          | normative | Artifact provenance wrapping              |
| `approval_artifact.schema.json`   | L1          | normative | Human approval artifact structure         |
| `effect.schema.json`              | L1          | normative | Effect definition and parameters          |
| `env_snap.schema.json`            | L1          | normative | Environment snapshot for determinism      |
| `envelope_ref.schema.json`        | L1          | normative | Envelope cross-reference                  |
| `envsnap.schema.json`             | L1          | normative | Environment snapshot (compact)            |
| `error_ir.schema.json`            | L1          | normative | Error intermediate representation         |
| `evidence_pack.schema.json`       | L1          | normative | Evidence pack for decisions               |
| `evidence_view.schema.json`       | L1          | normative | Evidence view projection                  |
| `money.schema.json`               | L1          | normative | Monetary amount (integer cents)           |
| `secret_ref.schema.json`          | L1          | normative | Secret reference (never contains secrets) |
| `workflow_definition.schema.json` | L2          | normative | Workflow DAG definition                   |

### Kernel (`kernel/`)

| Schema                        | Conformance | Status    | Description                        |
| ----------------------------- | ----------- | --------- | ---------------------------------- |
| `effect_boundary.schema.json` | L1          | normative | EffectBoundary wire format         |
| `event_envelope.schema.json`  | L1          | normative | Kernel event envelope              |
| `prng_config.schema.json`     | L2          | normative | PRNG configuration for determinism |

### Boundary (`boundary/`)

| Schema | Conformance | Status | Description |
| --- | --- | --- | --- |
| `extauthz.v1.schema.json` | L1 | preview | Gateway-to-Kernel external authorization contract |

### Policy (`policy/`)

| Schema                               | Conformance | Status    | Description                 |
| ------------------------------------ | ----------- | --------- | --------------------------- |
| `pdp_request.schema.json`            | L1          | normative | PDP request format          |
| `pdp_response.schema.json`           | L1          | normative | PDP response format         |
| `policy_bundle.schema.json`          | L1          | normative | Policy bundle definition    |
| `policy_decision.schema.json`        | L1          | normative | Decision record format      |
| `policy_input_bundle.v1.schema.json` | L1          | normative | Policy evaluation input     |
| `decision_log_event.schema.json`     | L2          | normative | Decision audit log event    |
| `DLPPolicy.v1.json`                  | L2          | normative | Data loss prevention policy |
| `ErrorBudgetPolicy.v1.json`          | L2          | normative | Error budget policy         |
| `ModelPolicy.v1.json`                | L2          | normative | Model governance policy     |
| `SLI.v1.json`                        | L2          | normative | Service level indicator     |
| `SLO.v1.json`                        | L2          | normative | Service level objective     |
| `backoff_policy.schema.json`         | L3          | normative | Retry backoff configuration |
| `retry_plan.schema.json`             | L3          | normative | Retry plan specification    |
| `timeout_policy.schema.json`         | L3          | normative | Timeout configuration       |

### Receipts (`receipts/`, `receipt/`)

| Schema                                    | Conformance | Status    | Description                       |
| ----------------------------------------- | ----------- | --------- | --------------------------------- |
| `receipt/v2.json`                         | L1          | normative | Receipt format v2                 |
| `canonical_semantic_receipt.schema.json`  | L1          | normative | Canonical semantic receipt        |
| `model_invocation_receipt.v1.schema.json` | L1          | normative | Model invocation receipt          |
| `tool_invocation_receipt.v1.schema.json`  | L1          | normative | Tool invocation receipt           |
| `managed_agent_execution_receipt.v1.schema.json` | L2 | preview | Managed Agent self-hosted worker execution receipt |
| `deployment_receipt.v1.json`              | L2          | normative | Deployment receipt                |
| `raw_record_layer.schema.json`            | L2          | normative | Raw record layer                  |
| `corroborated_receipt/v1.json`            | L2          | normative | Multi-source corroborated receipt |
| `deletion_receipt/v1.json`                | L2          | normative | Data deletion receipt             |

### Managed Agents (`managed-agents/`)

| Schema                                             | Conformance | Status  | Description                                        |
| -------------------------------------------------- | ----------- | ------- | -------------------------------------------------- |
| `claude_self_hosted_live_config.v1.schema.json`    | L2          | preview | Redacted live evidence config for Claude workers   |

### Workstation (`workstation/`)

| Schema                                             | Conformance | Status    | Description                                        |
| -------------------------------------------------- | ----------- | --------- | -------------------------------------------------- |
| `agent_run_receipt.v1.schema.json`                 | L2          | preview   | Manifest-first workstation agent run receipt       |
| `workstation_policy_decision_receipt.v1.schema.json` | L2        | preview   | Selected-effect workstation policy decision receipt |
| `scope_audit_report.v1.schema.json`                | L2          | preview   | Agent Scope Audit report over workstation receipts |

### Effects (`effects/`)

| Schema                            | Conformance | Status        | Description                                               |
| --------------------------------- | ----------- | ------------- | --------------------------------------------------------- |
| `effect_type_catalog.schema.json` | L1          | normative     | Effect type registry                                      |
| `effect_type_definition/v2.json`  | L1          | normative     | Effect type definition                                    |
| `effect_digest/v1.json`           | L1          | normative     | Effect digest for hashing                                 |
| Infrastructure effects            | L3          | normative     | `create_droplet`, `scale_cluster`, `deploy_release`, etc. |
| Chaos effects                     | L3          | informational | `chaos_kill_node`, `chaos_network_delay`                  |

### Evidence (`evidence/`)

| Schema | Conformance | Status | Description |
| --- | --- | --- | --- |
| `external_host_receipt.v1.json` | L2 | preview | Vendor-neutral host-observed event receipt |
| `external_receipt_chain.v1.json` | L2 | preview | Signed external host receipt chain envelope |
| `network_egress_event.v1.json` | L2 | preview | Host-observed outbound network event |
| `hardware_root_claim.v1.json` | L3 | preview | Structural hardware root-of-trust claim |
| `host_correlation_result.v1.json` | L2 | preview | HELM authority to host evidence correlation result |

### Compliance (`compliance/`)

| Schema                      | Conformance | Status    | Description                   |
| --------------------------- | ----------- | --------- | ----------------------------- |
| `ComplianceControl.v1.json` | L1          | normative | Compliance control definition |
| `ControlMapping.v1.json`    | L1          | normative | Control-to-regulation mapping |

### Access (`access/`)

| Schema                            | Conformance | Status    | Description                     |
| --------------------------------- | ----------- | --------- | ------------------------------- |
| `OperatorAccessPolicy.v1.json`    | L2          | normative | Operator access policy          |
| `PrivilegedAccessReceipt.v1.json` | L2          | normative | Privileged access audit receipt |
| `PrivilegedAccessRequest.v1.json` | L2          | normative | Privileged access request       |

### Orchestration (`orchestration/`)

| Schema                      | Conformance | Status    | Description                                |
| --------------------------- | ----------- | --------- | ------------------------------------------ |
| `PlanSpec.v2.json`          | L2          | normative | Plan specification                         |
| `plan_transaction.v1.json`  | L2          | normative | Plan read/write and verification contract  |
| `StepRun.v2.json`           | L2          | normative | Step execution record                      |
| `SignedEnvelope.v1.json`    | L1          | normative | Signed envelope wrapper                    |
| `Checkpoint.v1.json`        | L2          | normative | Orchestration checkpoint                   |
| Other orchestration schemas | L2          | normative | Escalation, Triage, Context, Lineage, etc. |

### Verification (`verification/`)

| Schema                         | Conformance | Status    | Description                          |
| ------------------------------ | ----------- | --------- | ------------------------------------ |
| `proof_obligation.schema.json` | L3          | normative | Formal proof obligation input        |
| `proof_result.schema.json`     | L3          | normative | Formal proof verifier result         |
| `verification_scope.v1.json`   | L2          | normative | Verification coverage and risk scope |

### Telemetry (`telemetry/`)

| Schema                  | Conformance | Status    | Description                    |
| ----------------------- | ----------- | --------- | ------------------------------ |
| `harness_trace.v1.json` | L2          | normative | Hash-linked harness trace data |

### Harness (`harness/`, `actions/`, `receipts/`)

| Schema                              | Conformance | Status    | Description                                      |
| ----------------------------------- | ----------- | --------- | ------------------------------------------------ |
| `harness_change_contract.v1.json`   | L2          | normative | Controlled harness mutation contract            |
| `grounded_action_ref.v1.json`       | L3          | normative | Visual and DOM/AX grounding for GUI actions     |
| `gui_action_receipt.v1.json`        | L3          | normative | Receipt for grounded GUI/computer-use execution |

### Organization & Governance (`orgdna/`, `profiles/`, `jurisdiction/`)

| Schema                                         | Conformance | Status    | Description                   |
| ---------------------------------------------- | ----------- | --------- | ----------------------------- |
| `orgdna/orggenome.v1.schema.json`              | L2          | normative | Organization genome           |
| `orgdna/orgphenotype.schema.json`              | L2          | normative | Compiled organization runtime |
| `orgdna/module.schema.json`                    | L2          | normative | Organization module           |
| `orgdna/environment_profile.schema.json`       | L2          | normative | Environment bindings          |
| `morphogenesis/confluence_strategy.schema.json` | L2         | normative | Morphogenesis confluence      |
| `jurisdiction/v1.json`                         | L1          | normative | Jurisdiction binding          |
| `profiles/industry_profile.v1.schema.json`     | L2          | normative | Industry profile              |
| `profiles/jurisdiction_profile.v1.schema.json` | L2          | normative | Jurisdiction profile          |

### Cybernetics (`cybernetics/`)

| Schema                                      | Conformance | Status    | Description                     |
| ------------------------------------------- | ----------- | --------- | ------------------------------- |
| `essential_variable.schema.json`            | L2          | normative | Bounded viability variable      |
| `control_loop.schema.json`                  | L2          | normative | Homeostatic control loop        |
| `mode.schema.json`                          | L2          | normative | Regulation operating mode       |
| `regulation_graph.schema.json`              | L2          | normative | Governed regulation state graph |

### Safety & Security (`safety/`, `perimeter/`)

| Schema                                 | Conformance | Status    | Description               |
| -------------------------------------- | ----------- | --------- | ------------------------- |
| `controllability_envelope.schema.json` | L1          | normative | Controllability envelope  |
| `PerimeterPolicy.v1.json`              | L2          | normative | Security perimeter policy |

### Finance, Knowledge, Memory, Packs

| Schema                       | Conformance | Status    | Description                    |
| ---------------------------- | ----------- | --------- | ------------------------------ |
| `finance/budget.schema.json` | L1          | normative | Budget definition              |
| `knowledge/*.schema.json`    | L2          | normative | Knowledge graph schemas        |
| `memory/*.json`              | L3          | normative | Memory retrieval schemas       |
| `packs/*.schema.json`        | L2          | normative | Pack manifest and type schemas |

### Spend (`spend/`)

| Schema                                       | Conformance | Status  | Description                                                                 |
| -------------------------------------------- | ----------- | ------- | --------------------------------------------------------------------------- |
| `spend_authority_contracts.v1.schema.json`   | L2          | preview | Spend envelopes, route quotes, receipts, provider terms, balances, and deferred credit lines |

### Authority (`authority/`)

| Schema                                             | Conformance | Status    | Description                             |
| -------------------------------------------------- | ----------- | --------- | --------------------------------------- |
| `authority_evaluation.v1.schema.json`              | L2          | normative | Authority evaluation request/decision   |
| `side_effect_authority_record.schema.json`         | L2          | preview   | Registered side-effect authority record |

### Reason Codes (`reason-codes/`)

| Schema                        | Conformance | Status    | Description                   |
| ----------------------------- | ----------- | --------- | ----------------------------- |
| `reason-codes-v1.schema.json` | L1          | normative | Reason code validation schema |
| `reason-codes-v1.json`        | L1          | normative | Reason code registry data     |

### API Surface (`effects/`)

| Schema         | Conformance | Status    | Description                       |
| -------------- | ----------- | --------- | --------------------------------- |
| `openapi.yaml` | L1          | normative | EffectBoundary REST API (OAS 3.1) |

### Connectors (`connectors/`)

| Schema                                                | Conformance | Status    | Description                              |
| ----------------------------------------------------- | ----------- | --------- | ---------------------------------------- |
| `connectors/ton/acton_command.schema.json`           | L2          | normative | TON Acton typed command envelope         |
| `connectors/ton/acton_receipt.schema.json`           | L2          | normative | TON Acton deterministic connector receipt |
| `connectors/ton/acton_contract_bundle.schema.json`   | L2          | normative | TON Acton connector contract bundle      |
| `connectors/ton/acton_script_manifest.schema.json`   | L2          | normative | TON Acton network script sidecar manifest |
| `connectors/ton/acton_evidence.schema.json`          | L2          | normative | TON Acton EvidencePack artifact index    |

---

**Total schemas**: 140 files across 29 domains.
**L1 (Core)**: 42 schemas
**L2 (Extended)**: 73 schemas
**L3 (Optional)**: 19 schemas
**Informational**: 6 schemas
