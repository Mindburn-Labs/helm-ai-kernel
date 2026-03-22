# Golden Evidence Packs

Pre-generated reference artifacts for deterministic verification testing.

## What is a golden pack?

A golden evidence pack is a known-good EvidencePack produced by `helm demo organization --template starter --provider mock`. It contains:

- Signed receipts (Ed25519, Lamport-ordered)
- Decision records with ProofGraph linkage
- Conformance report (L1/L2 gate results)
- Deterministic output hashes

## Purpose

1. **Regression gate** — `helm verify` must pass against golden packs on every release
2. **Reference implementation** — shows what a valid EvidencePack looks like
3. **Offline verification demo** — ship the pack, verify without network

## Generating a new golden pack

```bash
# From repo root:
make build
./bin/helm onboard --yes
./bin/helm demo organization --template starter --provider mock
./bin/helm export --evidence ./data/evidence --out artifacts/golden/starter-organization.tar
./bin/helm verify --bundle artifacts/golden/starter-organization.tar
```

## Verification

```bash
# Verify the golden pack
./bin/helm verify --bundle artifacts/golden/starter-organization.tar

# Run conformance against it
./bin/helm conform --level L1 --json
./bin/helm conform --level L2 --json
```

## Lifecycle

Golden packs should be regenerated when:

1. Receipt schema changes (new fields, different signing)
2. ProofGraph structure changes
3. Demo template changes
4. Major version bump

Always verify packs pass `helm verify` before committing.

## Caveats

Golden packs contain mock provider outputs (no real LLM calls). Timestamps and receipt IDs will differ between generations, but the structural shape and hash linkage patterns are canonical.
