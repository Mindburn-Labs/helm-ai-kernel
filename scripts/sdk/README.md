# SDK Tooling

`scripts/sdk` owns SDK type regeneration from the retained OpenAPI contract.

## Generator

```bash
bash scripts/sdk/gen.sh
```

The script uses Docker image `openapitools/openapi-generator-cli:v7.4.0` and
reads `api/openapi/helm.openapi.yaml`.

## Outputs

| Output | Source |
| --- | --- |
| `sdk/ts/src/types.gen.ts` | OpenAPI models |
| `sdk/python/helm_sdk/types_gen.py` | OpenAPI models |
| `sdk/go/client/types_gen.go` | OpenAPI models |
| `sdk/rust/src/types_gen.rs` | OpenAPI models |
| `sdk/java/src/main/java/labs/mindburn/helm/TypesGen.java` | OpenAPI models |

Protobuf bindings are owned by the `make codegen-*` targets in `Makefile`, not
by this script.

## Validation

```bash
make codegen-check
make test-sdk-go-standalone
make test-sdk-py
make test-sdk-ts
make test-sdk-rust
make test-sdk-java
make docs-coverage docs-truth
```
