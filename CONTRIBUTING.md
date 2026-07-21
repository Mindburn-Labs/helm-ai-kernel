# Contributing

HELM is maintained as a small OSS kernel. Contributions should improve the retained public surface, not reintroduce removed product or marketing scope.

If you are new, start with a scoped issue: [good first issue](https://github.com/Mindburn-Labs/helm-ai-kernel/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22). Ask setup questions in [Discussions](https://github.com/Mindburn-Labs/helm-ai-kernel/discussions) before opening a large PR.

## Local Setup

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
make build
```

## Validation Before a PR

```bash
make quality-pr
```

Run `make quality-impact` for a quick path-scoped package pass, or use focused targets such as `make quality-contracts`, `make quality-security`, or `make quality-typecheck` for the area you changed. Before merge or release, maintainers use `make quality-merge` and `make quality-release`.

## First Contribution Paths

| Path | Good first work | Focused validation |
| --- | --- | --- |
| Docs | Clarify quickstart, MCP, proxy, receipt, or verifier text. | `make docs-coverage docs-truth` |
| Examples | Add or polish localhost fixtures for ALLOW, DENY, and ESCALATE. | `make launch-smoke` or a focused launch demo |
| MCP | Improve quarantine, schema-pin, or authorization examples. | `bash scripts/launch/demo-mcp.sh` |
| Proxy | Improve OpenAI-compatible base URL examples. | `bash scripts/launch/demo-openai-proxy.sh` |
| Receipts | Add verification or tamper-failure fixtures. | `bash scripts/launch/demo-proof.sh` |
| SDKs | Polish first-run SDK examples. | `make sdk-examples-smoke` or a focused SDK target |

Public contribution lanes and community expectations are in [COMMUNITY.md](COMMUNITY.md). The ecosystem map for upstream work is in [docs/ECOSYSTEM.md](docs/ECOSYSTEM.md).

## Issue Labels

- `good first issue` is scoped and newcomer-safe.
- `help wanted` is contributor-ready, but may need more context or maintainer review.
- `maintainer-task` requires maintainer, operator, or release access and is not externally claimable.

## Contribution Rules

1. Keep documentation tied to code, tests, or release automation.
2. Do not merge incomplete behavior, backlog markers, or deferred public copy.
3. Keep the OSS scope tight: kernel, CLI, contracts, SDKs, and the retained deployment/examples surface.
4. Preserve deterministic verification paths when changing receipts, schemas, or evidence handling.

## Developer Certificate of Origin (DCO)

Contributions are accepted under the repository license (Apache-2.0),
inbound = outbound. There is no CLA and no copyright assignment — the DCO
is deliberate: it removes any unilateral relicensing option.

Every commit must carry a `Signed-off-by` trailer certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):

```bash
git commit -s
# amend the last commit if you forgot:
git commit --amend -s
```

CI rejects pull requests containing commits without a sign-off.

DCO sign-offs and other commit trailers are license and provenance evidence.
They do not authorize a merge or replace the active GitHub merge policy.

## Pull Requests

- **Current transition rule**: The human GitHub approval rule on `main` remains enforced, including its approval, required code owner review, and last-push protections. Direct merges are blocked. Do not remove or bypass this rule during implementation or evaluation.
- **Future machine authority**: The human rule can be replaced only after a source-owned machine permit bound to the exact PR head and an exact-head GitHub App interlock are live-proven by configuration and runtime readbacks. This authority is not live today.
- **DCO**: every commit is signed off (`git commit -s`); see above.
- Keep PRs narrow and reviewable.
- Include the commands you ran.
- Update docs only when the implementation or release truth changes.
- Link the issue or discussion that explains the user-facing value.
- Keep launch and community copy factual: no unsupported SaaS, hosted control-plane, certification, or production-security claims.

## Security Reports

Use the process in [SECURITY.md](SECURITY.md), not public issues.
