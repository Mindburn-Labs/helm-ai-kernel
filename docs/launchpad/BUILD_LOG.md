---
title: Launchpad Build Log
last_reviewed: 2026-05-22
---

# Launchpad Build Log

## 2026-05-22: Unified Launchpad Repo-Truth Pass

Scope:

- Kept one Kernel Console Launchpad route and existing Launchpad API family.
- Refactored the Console surface into shared components for app cards, simple
  launch flow, run timeline, proof, developer disclosure, and entitlement gate
  rendering.
- Removed hardcoded Hermes-only Simple Mode claims and green-path copy.
- Removed raw secret input behavior from Simple Mode. Secret setup now binds
  environment variable names through the existing secret route contract.
- Removed the UI-only custom AppSpec launch card from the registry app grid.
- Added optional TypeScript fields for future backend entitlement decisions.
  Production code does not infer account tier.
- Documented Mindburn hosted account and entitlement integration as target
  architecture in `MINDBURN_ACCOUNT_ENTITLEMENTS_SPEC.md`.

Repo-truth boundary:

- Current Kernel implementation has Launchpad/LaunchKit, supported registry
  apps, proof refs, EvidencePack export, MCP, sandbox, secrets, and teardown.
- Current Kernel implementation does not have production Free / Individual /
  Enterprise hosted entitlement routes.
- Fixture-only entitlement states are allowed in tests and must remain labeled
  as fixtures.

Verification targets:

```bash
cd apps/console
npm run typecheck
npm run test
npm run build
npm run smoke
npm run smoke:browser
go test ./core/cmd/helm-ai-kernel ./core/pkg/api ./core/pkg/launchkit ./core/pkg/launchpad/... -count=1
make test-console
make docs-truth
make launch-api-truth
make release-readiness
```
