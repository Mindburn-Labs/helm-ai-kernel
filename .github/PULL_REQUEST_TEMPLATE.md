## Summary

Describe the user-visible behavior, contract, documentation, or governance
change.

## Validation

List the commands you ran, or explain why a command was not applicable.

```bash
make quality-pr
```

## Checklist

- [ ] The change stays within the kernel scope in `README.md` and `docs/KERNEL_SCOPE.md`.
- [ ] Public docs, SDKs, schemas, or examples are updated when behavior changes.
- [ ] Launchpad live local-container changes were reviewed against `docs/launchpad/launch-conformance.md`.
- [ ] Contributor-facing docs or issue links are updated when this improves a first-run or first-PR path.
- [ ] Release version surfaces are lockstep (`make version-drift`) when touching `VERSION`, release workflows, chart metadata, SDK manifests, OpenAPI, or publishing docs.
- [ ] Security-sensitive material is not included in the PR.
- [ ] Breaking public interface changes are called out in `CHANGELOG.md`.
- [ ] Advisory quality warnings are acknowledged or tracked when relevant.
