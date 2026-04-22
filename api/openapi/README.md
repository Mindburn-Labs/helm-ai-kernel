# OpenAPI Contract

`helm.openapi.yaml` is the retained HTTP contract for the OSS kernel.

The generated SDKs in `sdk/` are derived from this file. If the contract changes, regenerate the SDKs and run the package validation targets before merging.

## Paths Covered Here

- proxy/chat completion surface
- health and version endpoints
- evidence export and verification endpoints
- proof-graph and conformance endpoints
- retained OSS-local viewer endpoints
