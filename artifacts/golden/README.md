# Golden Artifacts

This directory is reserved for locally generated golden artifacts used during verification work.

Tracked binary artifacts are intentionally not kept in git. Regenerate them locally when needed.

## Generate

```bash
make build
./bin/helm-ai-kernel onboard --yes
./bin/helm-ai-kernel demo organization --template starter --provider mock
./bin/helm-ai-kernel export --evidence ./data/evidence --out artifacts/golden/starter-organization.tar
./bin/helm-ai-kernel verify --bundle artifacts/golden/starter-organization.tar
```
