# Provider Starters

These are example-only starter layouts. They show the HELM config shape and CI
smoke commands for provider profiles; they do not certify provider SDKs or
claim full framework ownership.

## Starter Matrix

| Starter | Config | Smoke command |
| --- | --- | --- |
| Anthropic | `anthropic/helm.yaml` | `bash examples/starters/anthropic/ci-smoke.sh` |
| Codex | `codex/helm.yaml` | `bash examples/starters/codex/ci-smoke.sh` |
| Google ADK / A2A | `google/helm.yaml` | `bash examples/starters/google/ci-smoke.sh` |
| OpenAI | `openai/helm.yaml` | `bash examples/starters/openai/ci-smoke.sh` |

## Validation

Build the local binary first, then run the smoke scripts:

```bash
make build
bash examples/starters/anthropic/ci-smoke.sh
bash examples/starters/codex/ci-smoke.sh
bash examples/starters/google/ci-smoke.sh
bash examples/starters/openai/ci-smoke.sh
```

The smoke scripts check that `helm-ai-kernel init <profile>` creates `helm.yaml` and
`.env` in a temporary project and that `helm-ai-kernel doctor` can inspect it.
