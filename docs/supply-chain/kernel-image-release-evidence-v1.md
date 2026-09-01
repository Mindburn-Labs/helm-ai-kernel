# HELM AI Kernel image release evidence v1

Predicate type URI:
`https://github.com/Mindburn-Labs/helm-ai-kernel/blob/main/docs/supply-chain/kernel-image-release-evidence-v1.md`

This custom in-toto predicate records the checks completed against a staged
Kernel OCI digest before the immutable `sha-<SOURCE_SHA>` tag may be created.
That governed tag namespace is exclusive to `release-ai-os-image.yml`; the
legacy dispatch publisher uses `dev-sha-<SOURCE_SHA>`.
Cosign attaches it to the multi-platform image-index digest and the workflow
decodes the verified payload to require exact predicate and subject-digest
equality. The GitHub Actions artifact is only a convenience copy; the OCI
attestation is the durable release record.

Required evidence fields identify the Kernel component, exact source
repository/ref/SHA, explicit producer workflow name/file/ref/SHA/identity/run,
image repository, staging and final tags, index digest, both platform digests
and SPDX files, exact OCI source/revision labels, entrypoint/default command,
health and persistence contracts, the request and triggering GitHub actors, the
`release-production` environment, the SLSA build type, Cosign verification
state, and promotion status. The top-level object is closed: the interim form
has exactly the declared fields and `promotion_status=staging-digest-verified`;
the finalized form adds only `final_tag_digest` and uses the finalized promotion
status.

Before any release-evidence predicate is generated, the workflow reads both
platform manifests' final OCI configs and requires the governed entrypoint,
command, non-root user, data-directory environment, and exposed ports. It then
runs the exact linux/amd64 digest through the source-owned container smoke:
health checks, a fail-closed governed denial, stop, restart against the same
bind mount, root-key continuity, and exact denial-receipt read-back must all
pass. The predicate's `runtime_verification` field records those completed
checks; it is not inferred from the Dockerfile.

The `cve_gate` object is also closed and records `tool=grype`,
`scope=os-and-library`, `fail_on=high`, `status=passed`, and one report name,
platform digest, and report SHA-256 digest for each exact platform. Both
platform digests must have passed the scan before signing, and the reports are
uploaded with the durable evidence convenience copy.

The `slsa` object records the source-owned build type, the index predicate and
attestation names, and one predicate/attestation name pair plus exact platform
digest for each `linux/amd64` and `linux/arm64` manifest. The workflow verifies
each attestation by requiring both byte-for-byte predicate equality and a
single subject whose digest is the expected platform digest. This exact
predicate check is repeated for the finalized release-evidence attestation
after immutable-tag promotion; a matching subject with a different predicate
does not authorize publication.

The workflow first attaches an interim predicate with
`promotion_status=staging-digest-verified`. After the immutable tag is created
or found already pointing at the same digest, it finalizes the predicate with
`final_tag_digest` and
`promotion_status=final-tag-digest-platforms-signature-and-evidence-verified`,
attaches that finalized predicate to the same image digest, and decodes the
registry-hosted attestation to require exact finalized-predicate equality.
The downloadable copy therefore matches a durable OCI attestation rather than
claiming a stronger state than the registry record.
