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
health and persistence contracts, SLSA build type, Cosign verification state,
and promotion status.

The workflow first attaches an interim predicate with
`promotion_status=staging-digest-verified`. After the immutable tag is created
or found already pointing at the same digest, it finalizes the predicate with
`final_tag_digest` and
`promotion_status=final-tag-digest-platforms-signature-and-evidence-verified`,
attaches that finalized predicate to the same image digest, and decodes the
registry-hosted attestation to require exact finalized-predicate equality.
The downloadable copy therefore matches a durable OCI attestation rather than
claiming a stronger state than the registry record.
