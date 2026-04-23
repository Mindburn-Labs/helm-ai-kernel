# Golden Artifacts

This directory is reserved for locally generated golden artifacts used during verification work.

Tracked binary artifacts are intentionally not kept in git. Regenerate them locally when needed.

## Generate

```bash
make build
./bin/helm onboard --yes
./bin/helm demo organization --template starter --provider mock
./bin/helm export --evidence ./data/evidence --out artifacts/golden/starter-organization.tar
./bin/helm verify --bundle artifacts/golden/starter-organization.tar
```
