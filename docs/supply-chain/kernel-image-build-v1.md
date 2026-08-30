# HELM AI Kernel image build type v1

Type URI:
`https://github.com/Mindburn-Labs/helm-ai-kernel/blob/main/docs/supply-chain/kernel-image-build-v1.md`

This document defines the source-owned SLSA v1 `buildType` emitted by
`.github/workflows/release-ai-os-image.yml`. It does not claim the GitHub
Actions Workflow build type. The workflow checks out one exact commit, builds
the root `Dockerfile` for `linux/amd64` and `linux/arm64`, and pushes one OCI
index to `ghcr.io/mindburn-labs/helm-ai-kernel` under a run-unique staging tag.

## Parameters

`externalParameters` contains exactly `source_sha`, a 40-character lowercase
Git commit supplied to the manual dispatch. It must equal both the dispatch
event's `github.sha` and a freshly fetched `refs/heads/main` tip.

`internalParameters` contains the fixed image repository, workflow identity,
dispatch-time workflow SHA, `Dockerfile`, and the two target platforms. The
single resolved dependency is:

```json
{
  "uri": "git+https://github.com/Mindburn-Labs/helm-ai-kernel@refs/heads/main",
  "digest": {
    "gitCommit": "0123456789abcdef0123456789abcdef01234567"
  }
}
```

The Cosign in-toto statement, rather than the predicate object, owns the
`subject` field. The workflow decodes the verified statement and requires its
only subject SHA-256 digest to equal the built multi-platform index digest. It
also requires the decoded predicate to equal the generated predicate byte
structure before promotion.

## Invocation and authority

The only trigger is `workflow_dispatch` from `refs/heads/main`. The publish job
uses the `release-production` environment and performs no checkout until all of
these external owner-managed settings pass:

1. The environment is protected by required human reviewers, self-review is
   disabled, and administrator bypass is disabled.
2. Its environment variable `HELM_RELEASE_AUTHORITY_ARMED` equals
   `release-production`.
3. Repository variable `HELM_AI_OS_IMAGE_RELEASE_ACTORS` is a JSON array of
   exact allowed GitHub logins, for example `["mindburnlabs","peycheff-com"]`.
   Both `github.actor` and `github.triggering_actor` must be present.

Those settings are an owner blocker outside this source-only change. Until
they are confirmed in GitHub, the workflow is intentionally not dispatchable.
The workflow requires no release secret: GHCR and keyless Cosign operations use
the job-scoped GitHub token and OIDC identity.

The immutable producer identity consumed by HELM AI OS assembly is:

```text
workflow name: AI OS Kernel image
workflow file: .github/workflows/release-ai-os-image.yml
workflow ref:  refs/heads/main
certificate:   https://github.com/Mindburn-Labs/helm-ai-kernel/.github/workflows/release-ai-os-image.yml@refs/heads/main
```
