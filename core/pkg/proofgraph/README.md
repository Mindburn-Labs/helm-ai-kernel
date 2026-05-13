# HELM AI Kernel ProofGraph Package Source Owner

## Audience

Use this file when changing proof nodes, attribution edges, graph storage, condensation, anchoring, CloudEvents export, GraphQL views, or research proof nodes.

## Responsibility

`core/pkg/proofgraph` owns graph-shaped evidence relationships used by receipts, evidence packs, replay, attribution, and trust explanations. Public docs should explain what a developer or auditor can inspect; this package owns the internal graph model.

## Public Status

Classification: `public-hub`.

Public docs should link here from:

- `helm-ai-kernel/verification`
- `helm-ai-kernel/reference/execution-boundary`
- `helm-ai-kernel/reference/protocols-and-schemas`
- `helm-ai-kernel/trust` pages exposed through the docs site

## Source Map

- Graph and node model: `graph.go`, `node.go`, `store.go`.
- Attribution and anchoring: `attribution/`, `anchor/`, `cloudevents/`.
- Condensed and replicated views: `condensation/`, `consensus/`, `crdt/`.
- Public inspection adapters: `graphql/`.
- Research-only nodes: `research_nodes.go`; keep these out of public claims unless surfaced by public docs and tests.

## Documentation Rules

- Public diagrams must distinguish receipt material, proof graph nodes, and EvidencePack archive contents.
- Do not expose research-node semantics as stable API without schema and conformance backing.
- Changes to graph hashes, attribution edges, or export formats require verifier and protocol docs updates.

## Validation

Run:

```bash
cd core
go test ./pkg/proofgraph -count=1
cd ..
make docs-coverage docs-truth
```
