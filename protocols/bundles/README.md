# Protocol Bundles Source Owner

## Audience

Use this file when changing bundle formats, bundle examples, or compatibility expectations for policy/evidence bundles.

## Responsibility

`protocols/bundles` owns reusable protocol bundle material. The public docs should describe supported bundle flows and link to this directory when a bundle shape is the source of truth.

## Validation

Run:

```bash
make docs-coverage
make docs-truth
```

If a public page claims bundle compatibility, the claim must map to this directory, `core/cmd/helm-ai-kernel/bundle_cmd.go`, or an executable example.
