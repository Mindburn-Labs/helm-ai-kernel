# Contributing

HELM is maintained as a small OSS kernel. Contributions should improve the retained public surface, not reintroduce removed product or marketing scope.

## Local Setup

```bash
git clone https://github.com/Mindburn-Labs/helm-oss.git
cd helm-oss
make build
```

## Validation Before a PR

```bash
make test
make test-all
make crucible
```

Run any additional target relevant to the area you changed, such as `make bench` for benchmark work or the package-specific SDK targets for SDK changes.

## Contribution Rules

1. Keep documentation tied to code, tests, or release automation.
2. Do not merge incomplete behavior, backlog markers, or deferred public copy.
3. Keep the OSS scope tight: kernel, CLI, contracts, SDKs, and the retained deployment/examples surface.
4. Preserve deterministic verification paths when changing receipts, schemas, or evidence handling.

## Pull Requests

- Keep PRs narrow and reviewable.
- Include the commands you ran.
- Update docs only when the implementation or release truth changes.

## Security Reports

Use the process in [SECURITY.md](SECURITY.md), not public issues.
