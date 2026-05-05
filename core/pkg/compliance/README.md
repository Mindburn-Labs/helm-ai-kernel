# HELM OSS Compliance Package Source Owner

## Audience

Use this file when changing compliance pack compilation, scorecards, regulatory mappings, obligation normalization, enforcement, evidence generation, or public compliance examples.

## Responsibility

`core/pkg/compliance` owns machine-readable compliance support in HELM OSS. Public docs can explain mappings and evidence generation, but this package owns the implementation model and tests.

## Public Status

Classification: `public-hub`.

Public docs should link here from:

- `helm-oss/compliance/eu-ai-act-high-risk-pack`
- `helm-oss/compliance/nist-ai-agent-critical-infrastructure`
- `helm-oss/compliance/nist-ai-rmf-iso-42001-crosswalk`
- `helm-oss/governance/cncf-application`
- `helm-oss/verification`

## Source Map

- Public API and scorecards: `api.go`, `scorecard.go`, `scorer.go`.
- Pack compilation and controls: `compiler/`, `controls/`, `templates/`.
- Evidence and enforcement: `evidence/`, `enforcement/`, `obligations/`, `normalize/`.
- Regulatory families: `euaiact/`, `gdpr/`, `hipaa/`, `sox/`, `dora/`, `mica/`, `cftc/`, `fca/`, `sec/`.
- Cryptographic/canonical helpers: `jcs/`, `jkg/`, `zkprovider/`.

## Documentation Rules

- Public docs must describe compliance outputs as engineering evidence and not legal advice.
- Do not claim certification, audit acceptance, or regulatory sufficiency unless the claim is backed by a public compliance pack, evidence path, and explicit wording in product docs.
- New regulatory packs need source-owner docs, tests, and public boundary notes before inclusion in LLM exports.

## Validation

Run:

```bash
cd core
go test ./pkg/compliance -count=1
cd ..
make docs-coverage docs-truth
```
