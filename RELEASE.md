# Release Process

The retained release process is tag-driven and version-file-driven.

## Prepare a Release

1. Update `VERSION`.
2. Update `CHANGELOG.md`.
3. Run:

```bash
make test
make test-all
make crucible
```

4. Confirm SDK package versions match `VERSION`.

## Create the Tag

```bash
VERSION=$(cat VERSION)
git tag "v${VERSION}"
git push origin "v${VERSION}"
```

## Expected Release Outputs

The release workflow is responsible for producing:

- platform binaries for the Go CLI
- checksums
- release assets attached to GitHub Releases

Package publication for npm, PyPI, crates.io, and Maven-compatible consumers is handled by the retained publish workflows, not by undocumented side channels.
