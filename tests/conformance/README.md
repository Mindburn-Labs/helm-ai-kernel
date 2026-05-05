# Conformance Source Owner

## Audience

Use this file when changing conformance profiles, golden vectors, negative vectors, replay checks, or public compatibility claims.

## Responsibility

`tests/conformance` owns executable proof that an implementation satisfies the OSS conformance profile. The public docs route is `helm-oss/conformance`.

## Validation

Run:

```bash
cd tests/conformance
go test ./...
```

Then run:

```bash
make docs-coverage
make docs-truth
```

Public docs may claim conformance only for profiles and checks represented in this directory.
