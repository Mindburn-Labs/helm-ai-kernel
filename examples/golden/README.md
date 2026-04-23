# Golden EvidencePack Fixture

This directory contains a golden EvidencePack for testing and demo purposes.

## Contents

- `manifest.json` — Pack manifest with session metadata
- `receipt_allow.json` — Sample ALLOW receipt
- `receipt_deny.json` — Sample DENY receipt

## Usage

```bash
# Verify the golden pack
helm verify --bundle examples/golden/

# Use in tests
cp -r examples/golden/ /tmp/test-evidence/
helm verify --bundle /tmp/test-evidence/
```

## What This Proves

- Causal chain integrity (Lamport clock ordering)
- Deterministic hash chain (SHA-256 preimage binding)
- Fail-closed governance (DENY receipt present)
- Skill lifecycle integration (SkillCandidate proposed)
- Maintenance loop integration (incident auto-resolved)
