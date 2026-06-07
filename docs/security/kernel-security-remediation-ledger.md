# Kernel Security Remediation Ledger

Source scan: `/Users/ivan/Code/Mindburn-Labs/.codex-security-scan/security_scan_report.portfolio_plus_addendum.md`

Scope rule: strict kernel findings whose IDs start with `HELM_AI_KERNEL-` or `helm-ai-kernel-FILE-`.

Status values:

- `already-fixed-with-regression`: covered by remediation checkpoints before this ledger.
- `remaining`: still requires implementation in the completion pass.
- `fixed`: implemented during the completion pass after this ledger was created.

Current branch baseline: `codex/kernel-security-remediation` at `ee2cfd6d`, before syncing the branch with the two missing `origin/main` commits.

| Finding ID | Status | Remediation surface |
|---|---|---|
| HELM_AI_KERNEL-SUBAGENT-0098 | already-fixed-with-regression | Runtime evaluate API auth and principal binding |
| HELM_AI_KERNEL-SUBAGENT-0084 | already-fixed-with-regression | Legacy Launchpad API auth |
| helm-ai-kernel-FILE-0784-A | already-fixed-with-regression | External host evidence trust roots |
| helm-ai-kernel-FILE-0669-A | already-fixed-with-regression | G1 conformance receipt signatures |
| helm-ai-kernel-FILE-0665-A | already-fixed-with-regression | KernelBridge unknown-tool fail-closed behavior |
| helm-ai-kernel-FILE-0657-A | already-fixed-with-regression | Channel gateway webhook signatures |
| helm-ai-kernel-FILE-0636-A | already-fixed-with-regression | Browser side-effect classification |
| helm-ai-kernel-FILE-0635-A | already-fixed-with-regression | Skill bundle trusted signature proofs |
| helm-ai-kernel-FILE-0634-A | already-fixed-with-regression | Connector release trusted signature proofs |
| helm-ai-kernel-FILE-0610-A | already-fixed-with-regression | JWKS HTTPS enforcement |
| helm-ai-kernel-FILE-0598-A | already-fixed-with-regression | AIP delegation signature checks |
| helm-ai-kernel-FILE-0590-A | already-fixed-with-regression | MCP delegation scope validation |
| helm-ai-kernel-FILE-0584-A | already-fixed-with-regression | PDP attestation admission checks |
| helm-ai-kernel-FILE-0551-A | already-fixed-with-regression | Attestation metadata signature binding |
| helm-ai-kernel-FILE-0549-B | already-fixed-with-regression | Admission profile requirement enforcement |
| helm-ai-kernel-FILE-0549-A | already-fixed-with-regression | Unsigned attestation denial |
| helm-ai-kernel-FILE-0545-A | already-fixed-with-regression | Unsupported perimeter controls fail closed |
| helm-ai-kernel-FILE-0543-A | already-fixed-with-regression | Artifact envelope signature binding |
| helm-ai-kernel-FILE-0514-A | already-fixed-with-regression | TelemetryPDP observe-only shadow mode |
| helm-ai-kernel-FILE-0432-A | already-fixed-with-regression | ZK receipt mock seal verification |
| HELM_AI_KERNEL-SUBAGENT-0100 | already-fixed-with-regression | Standalone Launchpad API auth |
| HELM_AI_KERNEL-SUBAGENT-0097 | already-fixed-with-regression | Control-plane policy bundle signature enforcement |
| HELM_AI_KERNEL-SUBAGENT-0091 | already-fixed-with-regression | GitHub EffectPermit scope enforcement |
| HELM_AI_KERNEL-SUBAGENT-0089 | already-fixed-with-regression | Control-plane policy update trust roots |
| HELM_AI_KERNEL-SUBAGENT-0087 | remaining | Claude-managed sandbox per-session filesystem isolation |
| HELM_AI_KERNEL-SUBAGENT-0086 | remaining | Claude-managed sandbox environment scrubbing |
| HELM_AI_KERNEL-SUBAGENT-0085 | already-fixed-with-regression | Guardian effect-digest intent binding |
| HELM_AI_KERNEL-SUBAGENT-0083 | already-fixed-with-regression | Privileged access signed receipt schema |
| HELM_AI_KERNEL-SUBAGENT-0080 | already-fixed-with-regression | TUF metadata signature verification |
| HELM_AI_KERNEL-SUBAGENT-0079 | already-fixed-with-regression | Rekor checkpoint signature verification |
| HELM_AI_KERNEL-SUBAGENT-0078 | remaining | Workstation receipt trust roots and signer defaults |
| HELM_AI_KERNEL-SUBAGENT-0036 | remaining | Workstation enforce operate-mode execution guard |
| HELM_AI_KERNEL-SUBAGENT-0030 | remaining | Signed trust registry mutations |
| HELM_AI_KERNEL-SUBAGENT-0029 | already-fixed-with-regression | Kernel Launchpad API auth |
| HELM_AI_KERNEL-SUBAGENT-0028 | already-fixed-with-regression | Autonomy control admin auth |
| HELM_AI_KERNEL-SUBAGENT-0022 | remaining | Launchpad mount-name containment |
| HELM_AI_KERNEL-SUBAGENT-0001 | remaining | Proxy DENY containment |
| HELM_AI_KERNEL-SUBAGENT-0092 | already-fixed-with-regression | Helm smoke helper image and kubeconfig hardening |
| HELM_AI_KERNEL-SUBAGENT-0099 | already-fixed-with-regression | Certify archive extraction bounds |
| helm-ai-kernel-FILE-0788-A | already-fixed-with-regression | Pinned TLA tools download verification |
| helm-ai-kernel-FILE-0640-A | already-fixed-with-regression | DOM trap evidence from real browser runs |
| helm-ai-kernel-FILE-0632-A | already-fixed-with-regression | AIGP evidence derived from node evidence |
| helm-ai-kernel-FILE-0602-A | already-fixed-with-regression | MCP audit receipt redaction |
| helm-ai-kernel-FILE-0594-A | already-fixed-with-regression | Launchpad cloud readiness probes |
| helm-ai-kernel-FILE-0586-A | already-fixed-with-regression | Signal health evidence from metrics |
| helm-ai-kernel-FILE-0575-A | already-fixed-with-regression | Sumo exporter TLS enforcement |
| helm-ai-kernel-FILE-0573-A | already-fixed-with-regression | Splunk exporter TLS enforcement |
| helm-ai-kernel-FILE-0571-A | already-fixed-with-regression | Loki exporter TLS enforcement |
| helm-ai-kernel-FILE-0569-A | already-fixed-with-regression | Elastic exporter TLS enforcement |
| helm-ai-kernel-FILE-0567-A | already-fixed-with-regression | Datadog exporter TLS enforcement |
| helm-ai-kernel-FILE-0492-A | already-fixed-with-regression | Polymarket order amount validation |
| helm-ai-kernel-FILE-0482-A | already-fixed-with-regression | Skill promotion evaluator evidence checks |
| helm-ai-kernel-FILE-0410-A | already-fixed-with-regression | mTLS SPIFFE peer identity binding |
| helm-ai-kernel-FILE-0390-A | already-fixed-with-regression | File audit hash-chain verification |
| helm-ai-kernel-FILE-0389-A | remaining | TON wallet secret detection |
| helm-ai-kernel-FILE-0378-A | remaining | AP2 payment signed payload binding |
| HELM_AI_KERNEL-SUBAGENT-0096 | already-fixed-with-regression | Helm Postgres TLS production guard |
| HELM_AI_KERNEL-SUBAGENT-0095 | already-fixed-with-regression | Helm Postgres Secret references |
| HELM_AI_KERNEL-SUBAGENT-0094 | already-fixed-with-regression | Guardian context provenance binding |
| HELM_AI_KERNEL-SUBAGENT-0093 | already-fixed-with-regression | Docker smoke local credential exposure |
| HELM_AI_KERNEL-SUBAGENT-0088 | already-fixed-with-regression | Runtime tenant identity binding |
| HELM_AI_KERNEL-SUBAGENT-0081 | remaining | Module attestation commit hash validation |
| HELM_AI_KERNEL-SUBAGENT-0037 | remaining | Workstation decision signing seed argv removal |
| HELM_AI_KERNEL-SUBAGENT-0035 | remaining | Workstation import signing seed argv removal |
| HELM_AI_KERNEL-SUBAGENT-0034 | remaining | Workstation receipt signing seed argv removal |
| HELM_AI_KERNEL-SUBAGENT-0033 | remaining | Shadow scan secret redaction |
| HELM_AI_KERNEL-SUBAGENT-0032 | remaining | Console login password argv removal |
| HELM_AI_KERNEL-SUBAGENT-0027 | remaining | Authority evaluation schema top-level binding |
| HELM_AI_KERNEL-SUBAGENT-0026 | remaining | Release cosign identity anchoring |
| HELM_AI_KERNEL-SUBAGENT-0025 | already-fixed-with-regression | MCP firewall canonical verdicts |
| HELM_AI_KERNEL-SUBAGENT-0023 | already-fixed-with-regression | Sandbox broker bearer-token validation |
| HELM_AI_KERNEL-SUBAGENT-0021 | remaining | Acton connector permit and grant binding |
| HELM_AI_KERNEL-SUBAGENT-0020 | already-fixed-with-regression | E2B HTTPS preflight enforcement |
| HELM_AI_KERNEL-SUBAGENT-0019 | already-fixed-with-regression | Daytona HTTPS preflight enforcement |
| HELM_AI_KERNEL-SUBAGENT-0018 | remaining | Claude-managed shim dispatcher policy |
| HELM_AI_KERNEL-SUBAGENT-0017 | already-fixed-with-regression | Inbound channel strict signature metadata |
| HELM_AI_KERNEL-SUBAGENT-0016 | remaining | Execute-payment schema payee and amount constraints |
| HELM_AI_KERNEL-SUBAGENT-0015 | already-fixed-with-regression | Helm external Postgres Secret handling |
| HELM_AI_KERNEL-SUBAGENT-0014 | remaining | TEE secret proxy plaintext storage |
| HELM_AI_KERNEL-SUBAGENT-0013 | fixed | EvidencePack trusted signature root enforcement |
| HELM_AI_KERNEL-SUBAGENT-0012 | remaining | Scoped MCP approval expiry and tool binding |
| HELM_AI_KERNEL-SUBAGENT-0011 | remaining | Reference-pack policy hash binding |
| HELM_AI_KERNEL-SUBAGENT-0010 | remaining | Python publish workflow dispatch input validation |
| HELM_AI_KERNEL-SUBAGENT-0009 | remaining | npm publish workflow dispatch input validation |
| HELM_AI_KERNEL-SUBAGENT-0008 | remaining | Maven publish workflow dispatch input validation |
| HELM_AI_KERNEL-SUBAGENT-0007 | remaining | Clean-install workflow dispatch input validation |
| HELM_AI_KERNEL-SUBAGENT-0006 | remaining | Crates publish workflow dispatch input validation |
| HELM_AI_KERNEL-SUBAGENT-0005 | remaining | Managed-agent receipt signer default |
| HELM_AI_KERNEL-SUBAGENT-0003 | remaining | Policy-reader RBAC Secret scope |
| HELM_AI_KERNEL-SUBAGENT-0002 | already-fixed-with-regression | Proxy receipt causal chain continuity |
| HELM_AI_KERNEL-SUBAGENT-0090 | already-fixed-with-regression | Pack verify authenticity fail-closed behavior |
| HELM_AI_KERNEL-SUBAGENT-0082 | already-fixed-with-regression | Python SDK path segment validation |
| HELM_AI_KERNEL-SUBAGENT-0024 | already-fixed-with-regression | WASI pack trust verifier |
| HELM_AI_KERNEL-SUBAGENT-0031 | already-fixed-with-regression | Doctor diagnostic seed redaction |
| HELM_AI_KERNEL-SUBAGENT-0004 | already-fixed-with-regression | Sandbox filesystem path containment |
