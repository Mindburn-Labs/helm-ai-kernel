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

## Binding Architecture Rules (R1–R12)

The HELM target architecture, accepted on 2026-09-24, sets these rules for new
work here. Each one is recorded in an ADR in the `Mindburn-Labs/docs`
repository. That repository is private, so each summary below stands on its own.
The rules are build and release requirements. They are not evidence that a
control exists today: current behaviour is what the code and its tests prove.

- **R1 — Every enforcement claim has a scoped evidence record.** A control names its owner, entry points, configuration, protected operations and bypass assumptions in `controls.yaml`. Its tests cover an allowed operation, a forbidden operation, removal of the control and the bypass cases that apply. Only the tested path is `enforced`; every other path is `observed-only` or `unmanaged`. ([ADR-0001](https://github.com/Mindburn-Labs/docs/blob/main/adr/ADR-0001-structural-honesty-control-registry.md))
- **R2 — Results say exactly what was checked.** Only the evidence verifier emits `VERIFIED`, `FAILED` or `UNVERIFIABLE`. `PASS` means the named tests actually ran. A constant verdict, an empty suite or a skipped required check never counts as success, and `ACCEPTED` belongs to business acceptance. ([ADR-0001](https://github.com/Mindburn-Labs/docs/blob/main/adr/ADR-0001-structural-honesty-control-registry.md))
- **R3 — Authority is never derived from content.** Mandates, limits, approvals and reservations are typed records bound to authenticated principals. Model output, tool results, documents and request bodies can only propose; they never grant, widen or satisfy authority. ([ADR-0003](https://github.com/Mindburn-Labs/docs/blob/main/adr/ADR-0003-cel-policy-mandates-as-data.md))
- **R4 — One of each.** There is one organization model, policy engine, signing envelope, hash-chain derivation, Merkle construction, model gateway, stop mechanism, reason-code registry and error format. Adding a second needs an ADR that retires the first. ([ADR-0009](https://github.com/Mindburn-Labs/docs/blob/main/adr/ADR-0009-trust-zones-and-kernel-budget.md))
- **R5 — Postgres is the ledger.** Every state that authorizes, reserves, consumes or records an effect is a Postgres row changed in a transaction. It is never held in process memory, in files or in a workflow engine's history. ([ADR-0002](https://github.com/Mindburn-Labs/docs/blob/main/adr/ADR-0002-postgres-ledger-river-jobs.md))
- **R6 — Idempotency before side effects.** A tenant-scoped idempotency key and request digest are stored in the admission transaction. A duplicate never creates a new dispatch, and recovery retries only under the adapter's proven idempotency contract. ([ADR-0002](https://github.com/Mindburn-Labs/docs/blob/main/adr/ADR-0002-postgres-ledger-river-jobs.md))
- **R7 — Decisions are pure functions.** `decide(input, snapshot)` does no I/O, reads no clock and uses no randomness. Replay re-runs it on the stored input and snapshot. ([ADR-0003](https://github.com/Mindburn-Labs/docs/blob/main/adr/ADR-0003-cel-policy-mandates-as-data.md))
- **R8 — Credentials live with the gateway.** Sandboxes, episode workers and the product API process never hold provider credentials or signing keys. Worker egress goes only through the gateway. ([ADR-0009](https://github.com/Mindburn-Labs/docs/blob/main/adr/ADR-0009-trust-zones-and-kernel-budget.md))
- **R9 — The tenant comes from the token.** Tenant and principal come only from the authenticated credential. Every tenant table is under FORCE RLS, and no package-level store holds tenant data. ([ADR-0002](https://github.com/Mindburn-Labs/docs/blob/main/adr/ADR-0002-postgres-ledger-river-jobs.md))
- **R10 — Unexplained unreachable shipped code blocks release.** Symbol-level reachability runs from the declared shipped binaries, build profiles and public APIs. Each finding is wired, removed, kept as a compatibility surface or isolated as an experiment, with an owner. ([ADR-0001](https://github.com/Mindburn-Labs/docs/blob/main/adr/ADR-0001-structural-honesty-control-registry.md))
- **R11 — The trusted core has a measured budget.** The core plus the verifier targets ≤ 20k non-test lines under a published counting rule. The full trusted boundary, including adapters and credential handling, is reported separately. ([ADR-0009](https://github.com/Mindburn-Labs/docs/blob/main/adr/ADR-0009-trust-zones-and-kernel-budget.md))
- **R12 — Signed payloads have explicit semantic coverage.** Every new signed type has a closed, versioned schema of its authoritative fields. Its exact payload bytes are signed as DSSE and retained. New fields need a new payload version, and legacy versions stay verify-only. ([ADR-0004](https://github.com/Mindburn-Labs/docs/blob/main/adr/ADR-0004-dsse-exact-payload-bytes.md))

The full ADR index, including the owner decisions in ADR-0010, is the "HELM
Target Architecture Decisions" section of `architecture/source-truth.md` in
the same repository.
