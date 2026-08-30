# HELM AI Kernel image release evidence v1

Predicate type URI:
`https://github.com/Mindburn-Labs/helm-ai-kernel/blob/main/docs/supply-chain/kernel-image-release-evidence-v1.md`

This custom in-toto predicate records the checks completed against a staged
Kernel OCI digest before the immutable `sha-<SOURCE_SHA>` tag may be created.
Cosign attaches it to the multi-platform image-index digest and the workflow
decodes the verified payload to require exact predicate and subject-digest
equality. The GitHub Actions artifact is only a convenience copy; the OCI
attestation is the durable release record.

Required evidence fields identify the Kernel component, exact source
repository/ref/SHA, explicit producer workflow name/file/ref/SHA/identity/run,
image repository, staging and final tags, index digest, both platform digests
and SPDX files, exact OCI source/revision labels, entrypoint/default command,
health and persistence contracts, SLSA build type, Cosign verification state,
and pre-promotion status.

The durable predicate's `promotion_status` is
`staging-digest-verified`, because the predicate is attached before promotion.
After the immutable tag is created or found already pointing at the same
digest, the downloadable copy additionally records `final_tag_digest` and
`final-tag-digest-platforms-signature-and-evidence-verified`. That convenience
copy does not retroactively change the already-attested predicate.
