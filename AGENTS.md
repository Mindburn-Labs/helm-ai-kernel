# Agent Operational Guidelines for helm-ai-kernel

Welcome to the **helm-ai-kernel** repository. This is the core, open-source execution firewall daemon.

## Developer Runbook
* Build daemon binary: `make build`
* Run comprehensive unit tests: `make test`
* Execute quality gates and linters: `make lint`
* Verify platform docs and fixture truth: `make test-platform`
* Verify conformance and use cases: `make crucible`

## Governance & Rules
1. API and Protobuf mutations originate here and flow into the unified `contracts-catalog`; do not invent contract truth in catalog mirrors.
2. Maintain strict zero-dependency boundaries on volatile commercial components.
3. Every functional path must maintain green unit/integration tests and high coverage metrics.
4. Treat RLM outputs as input evidence only. They become Kernel truth only when represented through existing verdict, receipt, ProofGraph, EvidencePack, contract, conformance, or verifier paths; do not add a separate RLM proof universe.
5. Treat `mindburnlabs` and `peycheff-com` as Ivan's human GitHub accounts and preserve both as Mindburn-Labs organization owners/admins. Before any GitHub Actions state mutation, release/tag/package/artifact mutation, production promotion, or organization/repository access or settings mutation, read and follow `/helm-privileged-ops`; obtain exact single-use human approval and verify the authoritative readback.
6. Kernel owns verdict, permit, gateway, receipt, ProofGraph, EvidencePack, and
   conformance semantics; it is not HELM's organization planner or business
   runtime. OrgGenome/OrgPhenotype schemas and GeneratedSpec/evidence paths do
   not make Kernel an `OrganizationRuntime` or prove a living company.
