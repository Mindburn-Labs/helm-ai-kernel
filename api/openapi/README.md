# OpenAPI Contract

`helm.openapi.yaml` is the retained HTTP contract for the OSS kernel.

The generated HTTP client/types layer in `sdk/` is derived from this file. Protobuf bindings are generated separately from `protocols/proto/`. If either contract changes, regenerate the affected SDK artifacts and run the package validation targets before merging.

## Paths Covered Here

- proxy/chat completion surface
- health and version endpoints
- evidence export and verification endpoints
- proof-graph and conformance endpoints
- retained OSS-local viewer endpoints
