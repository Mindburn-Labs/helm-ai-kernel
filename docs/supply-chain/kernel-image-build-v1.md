# HELM AI Kernel image build type v1

Type URI:
`https://github.com/Mindburn-Labs/helm-ai-kernel/blob/main/docs/supply-chain/kernel-image-build-v1.md`

This document defines the source-owned SLSA v1 `buildType` emitted by
`.github/workflows/release-ai-os-image.yml`. It does not claim the GitHub
Actions Workflow build type. The workflow checks out one exact commit, builds
the root `Dockerfile` for `linux/amd64` and `linux/arm64`, and pushes one OCI
index to `ghcr.io/mindburn-labs/helm-ai-kernel` under a run-unique staging tag.
Its build timestamp and BuildKit `SOURCE_DATE_EPOCH` both derive from that
commit's Git committer timestamp, so a retry does not inject wall-clock time
into the image digest. The workflow installs the Docker Buildx `v0.36.1`
linux/amd64 release artifact only after matching its source-pinned SHA-256, and
it creates the BuildKit `v0.32.2` worker from a digest-pinned image. A
same-source dispatch therefore cannot silently change either builder. The
pinned builder image already supplies the CA bundle; the Dockerfile performs no
live `apk add`, and Go module content remains bound by `core/go.sum`, so a
same-source retry does not resolve mutable Alpine packages.
The root `.dockerignore` starts with a deny-all rule and re-includes only the
Dockerfile's `core/`, policy, and reference-pack inputs. It explicitly excludes
the checkout's `.git` directory and generated Buildx, runtime, platform, SBOM,
SLSA, Grype, and release-evidence files from the build context.

After the platform manifests are inspected and before any Cosign signature is
created, the workflow downloads the Grype `v0.116.1` Linux amd64 release
archive from its immutable versioned URL and accepts it only after matching the
source-owned SHA-256
`0122df7b655981abe547ad3d2190d65551dac6a2bfc80b4dc2a989b5d0587458`. It
explicitly bootstraps the vulnerability database once
into the run's dedicated cache, records `grype db status --output json`, and
requires the exact provider-shaped machine-readable status object, including a
dotted numeric `schemaVersion` without a leading `v`. Both platform scans
then use that same cache with application and database auto-updates disabled; if the
binary, database bootstrap, or status readback is unavailable, the job stops.
Grype scans each exact `linux/amd64` and `linux/arm64` manifest digest with
`--scope all-layers --fail-on high --output json`. A scan is accepted only when
its report is an object with an array `matches` field containing no `high` or
`critical` severity. Each report and the database-status file are retained with
SHA-256 digests in the release evidence, so the CVE gate cannot silently change
from one platform to the other or from one retry to the next.

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

The workflow emits one source-owned SLSA v1 predicate for the multi-platform
index and one for each exact platform manifest. Each platform predicate records
its `linux/amd64` or `linux/arm64` value and the corresponding manifest digest
in `internalParameters`. Cosign attests all three predicates before signing is
accepted. The Cosign in-toto statement, rather than the predicate object, owns
the `subject` field. The workflow decodes every verified statement and requires
its only subject SHA-256 digest to equal the corresponding index or platform
digest. It also requires each decoded predicate to equal its generated
predicate byte structure before promotion.

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
4. The environment supplies `HELM_GITHUB_OWNER_READ_TOKEN`, a read-only token
   able to read the repository release-actor variable and Mindburn-Labs
   organization memberships. The workflow fails unless both `mindburnlabs` and
   `peycheff-com` read back as active admins.
5. The exact current workflow run's environment review history contains an
   approval from one of those two human owners. Reruns are rejected, so the
   approval endpoint remains bound to this immutable run rather than treating
   a repository variable or another run's approval as reusable authority.

Those settings are an owner blocker outside this source-only change. Until
they are confirmed in GitHub, the workflow is intentionally not dispatchable.
The owner-readback token is never used for mutation. GHCR and keyless Cosign
operations still use only the job-scoped GitHub token and OIDC identity.

The environment readback is authoritative, not a name-only check. The workflow
requires `can_admins_bypass=false`,
`deployment_branch_policy={protected_branches:false,custom_branch_policies:true}`,
and exactly two protection rules: one `required_reviewers` rule with
`prevent_self_review=true`, exact outer provider keys
`[id,node_id,prevent_self_review,reviewers,type]`, and exactly two outer
reviewer entries with keys `[reviewer,type]`. Their nested provider `User`
trust projections require positive integral identities, nonempty `node_id`
values, `type=User`, `site_admin=false`, and the exact login set
`[mindburnlabs,peycheff-com]`; reviewer IDs and node IDs must also be
distinct, while unrelated documented User metadata is tolerated. The
second rule is one `branch_policy` rule with exactly the provider keys
`[id,node_id,type]`, with a positive integral `id` and nonempty `node_id`. The
deployment-branch-policies endpoint must report one record with exactly the
provider keys `[id,name,node_id,type]`, a positive integral `id`, nonempty
`node_id`, and name/type exactly `main`/`branch`.

The dispatch snapshot and the owner-token live readback both require the exact
actor JSON `["mindburnlabs","peycheff-com"]`. Every policy, variable,
membership, and current-main ref read uses `GH_TOKEN="${OWNER_READBACK_TOKEN}"`
explicitly. The exact-run approvals response must contain an `approved` review
targeting `release-production` from one of those owners while differing from
both the request and triggering actors. Approval timestamps are not inferred
from unsupported top-level fields; any nested environment metadata timestamp
is informational only. The
full environment, branch-policy, actor, owner, approval, source-tip, and newest
CI readbacks are repeated immediately before the immutable `sha-<SOURCE_SHA>`
promotion. The initial live authority and SHA-256 of its exact actor JSON are
persisted through `GITHUB_ENV` and both are compared again at that final
checkpoint. Current-main REST ref readbacks and CI-run queries at both
checkpoints are bound explicitly to the owner readback token; the job token is
reserved for publication operations. Reruns are rejected.

This workflow exclusively owns the governed immutable `sha-<SOURCE_SHA>` tag
namespace. The legacy `release.yml` QA publisher uses the disjoint
`dev-sha-<SOURCE_SHA>` namespace and cannot create or overwrite a governed tag.

The immutable producer identity consumed by HELM AI OS assembly is:

```text
workflow name: AI OS Kernel image
workflow file: .github/workflows/release-ai-os-image.yml
workflow ref:  refs/heads/main
certificate:   https://github.com/Mindburn-Labs/helm-ai-kernel/.github/workflows/release-ai-os-image.yml@refs/heads/main
```
