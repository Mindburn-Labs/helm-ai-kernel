# Conformance Source Owner

## Audience

Use this file when changing conformance profiles, golden vectors, negative vectors, replay checks, or public compatibility claims.

## Responsibility

`tests/conformance` owns executable proof that an implementation satisfies the OSS conformance profile. The public docs route is `helm-ai-kernel/conformance`.

## Validation

Run:

```bash
cd tests/conformance
GOWORK=off go test ./...
```

`GOWORK=off` is not optional: the repo has a `go.work`, and without that flag
the module resolves against the workspace build list rather than its own
`go.mod`, so a local pass need not mean a CI pass.

This is the same command CI runs. `scripts/ci/go_module_tests.sh` discovers
every tracked `go.mod` and runs `GOWORK=off go test ./...` in each. It is the
`go-module-tests` gate of `make check`, which `.github/workflows/ci.yml` runs as
the required `ci / gate` check — so a red conformance package blocks the merge. See
[`.github/TEST_MATRIX.md`](../../.github/TEST_MATRIX.md) for the CI baseline
that job belongs to. A new package added under this directory is covered the
moment it lands — no workflow edit required.

Then run:

```bash
make docs-coverage
make docs-truth
```

Public docs may claim conformance only for profiles and checks represented in this directory.

`helm-ai-kernel conform --level L1|L2` and `helm-ai-kernel test conformance --level L1|L2`
were retired in HELM-756 with gates G1–G15 and GX; they exit 2. Public release
certification uses the signed G0 report from `make conformance-release-report`,
checked by `make conformance-release-gate`.
