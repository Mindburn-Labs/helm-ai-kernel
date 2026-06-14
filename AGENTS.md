# Agent Operational Guidelines for helm-ai-kernel

Welcome to the **helm-ai-kernel** repository. This is the core, open-source execution firewall daemon.

## Developer Runbook
* Build daemon binary: `make build`
* Run comprehensive unit tests: `make test`
* Execute quality gates and linters: `make lint`
* Verify conformance and evidence packs: `make verify`

## Governance & Rules
1. All API and Protobuf mutations must sync to `contracts-proto` and `contracts-api-catalog`.
2. Maintain strict zero-dependency boundaries on volatile commercial components.
3. Every functional path must maintain green unit/integration tests and high coverage metrics.
4. Treat RLM outputs as input evidence only. They become Kernel truth only when represented through existing verdict, receipt, ProofGraph, EvidencePack, contract, conformance, or verifier paths; do not add a separate RLM proof universe.
