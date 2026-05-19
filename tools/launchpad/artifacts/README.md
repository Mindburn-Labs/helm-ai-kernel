# HELM Launchpad Artifact Recipes

These Dockerfiles are HELM-owned build recipes for pinned upstream app source
checkouts. They intentionally do not depend on upstream Dockerfiles for
promotion authority.

Promotion to `oss_supported` still requires a CI artifact manifest with:

- immutable `image@sha256`
- keyless cosign verification
- syft SBOM
- grype or trivy report
- upstream license ref
- live local-container e2e ref
- teardown receipt ref
- offline-verifiable EvidencePack ref
