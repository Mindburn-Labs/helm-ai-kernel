# HELM AI Kernel EvidencePack Package Source Owner

## Audience

Use this file when changing EvidencePack archive building, manifests, streaming, retention metadata, summaries, or verifier inputs.

## Responsibility

`core/pkg/evidencepack` owns the archive builder and reader for evidence bundles exported by HELM AI Kernel. Public docs should teach developers how to export, inspect, replay, and verify packs; this package owns the archive shape and streaming behavior.

## Public Status

Classification: `public-direct`.

Public docs should link here from:

- `helm-ai-kernel/developer-journey`
- `helm-ai-kernel/verification`
- `helm-ai-kernel/reference/execution-boundary`
- `helm-ai-kernel/reference/json-schemas`

## Source Map

- Archive construction: `archive.go`, `builder.go`, `stream_builder.go`.
- Archive reading: `stream_reader.go`, `stream_test.go`.
- Manifest and summaries: `manifest.go`, `summary.go`.
- Retention metadata: `retention/`.
- Fault behavior: `chaos_test.go` and edge-case coverage tests.

## Documentation Rules

- Public export examples must name the command, expected artifact, and verifier path.
- Do not claim a retention or archive field is stable unless it is backed by this package and a public schema or conformance fixture.
- Any archive layout change requires docs, schema, and replay validation updates.

## Validation

Run:

```bash
cd core
go test ./pkg/evidencepack -count=1
cd ..
make docs-coverage docs-truth
```
