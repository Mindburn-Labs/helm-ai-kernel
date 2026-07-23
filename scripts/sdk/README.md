# SDK Tooling

`scripts/sdk` owns SDK type regeneration from the retained OpenAPI contract.

## Generator

```bash
bash scripts/sdk/gen.sh
```

The script uses the Docker image
`openapitools/openapi-generator-cli:v7.4.0`, pinned by digest, and reads
`api/openapi/helm.openapi.yaml`. Generation is deterministic: for a fixed
spec and pinned generator image the outputs are byte-identical. The image can
be overridden for controlled upgrades via `HELM_OPENAPI_GENERATOR_IMAGE`.

Post-generation patches follow patch-as-assertion: every patch that is
expected to apply hard-fails when its anchor is missing, so generator or spec
drift breaks the build loudly instead of corrupting SDKs silently.

## Outputs

| Output | Source |
| --- | --- |
| `sdk/ts/src/types.gen.ts` | OpenAPI models |
| `sdk/python/helm_sdk/types_gen.py` | OpenAPI models |
| `sdk/go/client/types_gen.go` | OpenAPI models |
| `sdk/rust/src/types_gen.rs` | OpenAPI models |
| `sdk/java/src/main/java/labs/mindburn/helm/TypesGen.java` | OpenAPI models |

Each SDK also carries a `generated.manifest.json` at its package root,
written by `gen.sh`, recording the generator image, the spec hash, and the
sha256 of every generated file. Manifests are deterministic and committed
alongside the generated files.

Protobuf bindings are owned by the `make codegen-*` targets in `Makefile`, not
by this script.

## Drift gate

```bash
make sdk-gen-check        # regenerate all SDKs and fail on any diff (needs Docker)
make sdk-manifest-verify  # fast hash check of committed files vs manifests (no Docker)
make test-sdk-manifest    # unit tests for the manifest tool
```

`make sdk-gen-check` runs in CI as the `sdk-drift` job in
`.github/workflows/ci.yml`. When it fails, either regenerate and commit
(`bash scripts/sdk/gen.sh && git add sdk/`) after an intentional spec or
generator change, or revert manual edits to generated files.

## Validation

```bash
make codegen-check
make sdk-gen-check
make test-sdk-go-standalone
make test-sdk-py
make test-sdk-ts
make test-sdk-rust
make test-sdk-java
make docs-coverage docs-truth
```
