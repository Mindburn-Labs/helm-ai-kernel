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

The smoke scripts pass when `helm-ai-kernel init <profile>` creates nonempty
`helm.yaml` and `.env.helm.example` files in a temporary project. They also run
`helm-ai-kernel doctor` and print its exit status as a separate environment
diagnostic. Doctor returns 0 for healthy, 1 for warnings, and 2 for critical
failures.
