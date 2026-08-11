# Golden Artifacts

This directory is reserved for locally generated golden artifacts used during verification work.

Tracked binary artifacts are intentionally not kept in git. Regenerate them locally when needed. New local installations should use the guided `setup --quickstart` flow; this fixture recipe keeps the compatibility target because it pins the historical artifact layout.

## Generate

```bash
make build
make onboard
./bin/helm-ai-kernel demo organization --template starter --provider mock
./bin/helm-ai-kernel export --evidence ./data/evidence --out artifacts/golden/starter-organization.tar
./bin/helm-ai-kernel verify --bundle artifacts/golden/starter-organization.tar --allow-self-attested
```

The opt-in accepts the locally generated seal as proof of internal consistency,
not provenance.
