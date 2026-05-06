---
title: OSS Readiness Audit
last_reviewed: 2026-05-06
---

# OSS Readiness Audit

This audit records repository and remote-readiness gaps found during the
2026-05-06 review of `Mindburn-Labs/helm-oss`.

## Status Summary

| Area | Status | Owner | Verification |
| --- | --- | --- | --- |
| GitHub landing README | Fixed in repo | Maintainers | `gh api repos/Mindburn-Labs/helm-oss/readme` after push |
| Community health files | Fixed in repo | Maintainers | GitHub community profile API |
| Issue and PR templates | Fixed in repo | Maintainers | New issue/PR UI after push |
| Python publish workflow YAML | Fixed in repo | Maintainers | YAML parser and `gh workflow list` |
| Dependabot PR creation | Fixed in repo | Maintainers | Dependabot updates dashboard |
| Code scanning | Fixed in repo | Maintainers | Code scanning alerts page after workflow run |
| README install claims | Fixed in repo | Maintainers | Package/channel commands below |
| Branch protection | Configured as repository ruleset | Maintainers | Rulesets API |
| GitHub Actions billing lock | External blocker | Organization admins | Latest Actions run starts jobs |
| TEE vendor attestation | Known implementation gap | Kernel maintainers | Hardware-backed signature-chain tests |
| Public maintainer diversity | Known governance gap | Governance maintainers | `MAINTAINERS.md` |

## High-Priority Gaps

1. **Remote GitHub Actions are blocked by billing.** Latest `main` runs did not
   start jobs because the GitHub account was locked for billing. This must be
   resolved in GitHub billing settings before branch protection can provide a
   useful signal.
2. **Classic branch protection was disabled.** `main` is protected through an
   active repository ruleset requiring pull requests, status checks, no force
   pushes, and no branch deletion.
3. **TEE vendor attestation remains experimental.** SEV-SNP, TDX, and Nitro
   adapters parse or synthesize quote-shaped material, but production
   signature-chain validation against vendor roots is not implemented and
   hardware-tested.
4. **Maintainer diversity is not yet achieved.** `MAINTAINERS.md` currently
   lists the Mindburn Labs core team rather than two or more unaffiliated
   individual maintainers.

## Verification Commands

```bash
make docs-coverage docs-truth
python3 - <<'PY'
from pathlib import Path
import yaml
for path in sorted(Path(".github/workflows").glob("*.yml")):
    yaml.safe_load(path.read_text())
    print(path)
PY
brew info mindburn-labs/tap/helm
npm view @mindburn/helm version
python3 -m pip index versions helm-sdk
cargo search helm-sdk --limit 5
curl -I --max-time 10 https://jitpack.io/com/github/Mindburn-Labs/helm-oss/0.4.0/helm-oss-0.4.0.pom
```

After pushing, also check:

```bash
gh api repos/Mindburn-Labs/helm-oss/community/profile
gh api repos/Mindburn-Labs/helm-oss/readme
gh api repos/Mindburn-Labs/helm-oss/rulesets
gh run list --repo Mindburn-Labs/helm-oss --limit 10
```

## Package State Checked On 2026-05-06

| Surface | Observed state |
| --- | --- |
| Homebrew | `mindburn-labs/tap/helm` and `mindburnlabs/tap/helm` resolve to `0.4.0`; `mindburn/tap/helm` does not. |
| npm TypeScript SDK | `@mindburn/helm` resolves to `0.4.0`. |
| npm design-system core | `@helm/design-system-core` was not present in the public npm registry. |
| PyPI | `helm-sdk` resolves to `0.4.0`. |
| crates.io | `helm-sdk` resolves to `0.4.0`. |
| Go SDK | `go list` reported tagged versions that do not align with repository `VERSION`; use `@main` for current source until tags are corrected. |
| Java/JitPack | The checked JitPack release URL resolved for `com.github.mindburn-labs:helm-oss:0.4.0`; the Maven deploy workflow still owns `com.github.Mindburn-Labs:helm-sdk`. |

## Maintenance Rules

- Keep `README.md`, `docs/PUBLISHING.md`, and SDK docs aligned with verified
  registry state.
- Do not claim production TEE verification until strict-chain verification
  succeeds against real SEV-SNP, TDX, or Nitro artifacts.
- Update this audit when remote settings or package publication state changes.
