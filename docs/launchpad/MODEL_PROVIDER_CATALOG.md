# Launchpad Model Provider Catalog

Launchpad BYO model egress is governed by `core/pkg/launchpad/modelproviders/catalog.json`.

The catalog records the provider id, jurisdiction region, API protocol, runtime env names, required env groups, HTTPS base URLs, dynamic base URL envs, egress host suffixes, and official source URLs for primary US, EU, and China LLM API providers. Local-container egress preflight rejects model-provider destinations that are not in this catalog.

The scheduled `Launchpad Model Provider Catalog` workflow runs `scripts/launch/update_model_provider_catalog.py` daily. It normalizes the catalog, checks official source URLs, and opens a PR if the canonical catalog changes.
When run with `--network --write`, the updater also regenerates
`core/pkg/launchpad/modelproviders/source_fingerprints.json`. That file stores
stable SHA-256 fingerprints for the official provider docs listed in
`source_urls`. A diff in the fingerprint artifact is a review trigger: upstream
provider docs changed, so the catalog should be checked for new endpoints,
auth env names, regions, or API compatibility changes.

For Launchpad AppSpecs, `model_gateway.provider: byo` with no `provider_ids`, no
`model_gateway_env`, and no explicit `network_policy.allowlist` means "expand
from the current embedded catalog." The launch compiler materializes the exact
runtime env names and HTTPS base URLs into the LaunchPlan, and the local
container egress proxy still validates every destination against the catalog.

Providers with account- or region-specific endpoints must use
`required_env_groups` instead of a flat key-only entry. For example, Azure
OpenAI requires `AZURE_OPENAI_API_KEY + AZURE_OPENAI_ENDPOINT`; the endpoint is
accepted only when it matches the catalog's Azure OpenAI host suffix. Amazon
Bedrock, Google Vertex AI, and IBM watsonx are represented with their provider
specific auth/project/region groups rather than being forced through
OpenRouter.

CI can provide provider keys either as individual catalog env secrets or as a
single JSON secret named `HELM_LAUNCHPAD_CI_MODEL_PROVIDER_SECRET_JSON`, for
example `{"OPENAI_API_KEY":"...","AZURE_OPENAI_API_KEY":"...","AZURE_OPENAI_ENDPOINT":"https://example.openai.azure.com/"}`.
The clean-install and live-conformance gates only import env names that exist in
this catalog, and they require at least one complete provider env group. A new
provider can be enabled by the catalog refresh plus secret configuration,
without editing workflow YAML.

This is a direct-provider BYO allowlist. It does not imply that every app can speak every provider protocol yet; app runtime commands and model-gateway adapters still need provider-specific routing before a provider becomes usable end to end.
