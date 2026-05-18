# Homebrew Naming Plan

Status: [DEFER] distribution-only plan. Do not update the tap until Launchpad conformance passes.

## Package Identity

- [KEEP] Formula name: `helm-ai-kernel`.
- [KEEP] Tap target: `mindburnlabs/tap/helm-ai-kernel`.
- [KEEP] Installed binary: `helm-ai-kernel`.
- [KEEP] Launchpad command surface stays under `helm-ai-kernel launch ...`; do not introduce a separate `helm-launchpad` binary for MVP.

## Conflict Rules

- [KEEP] Homebrew remains distribution only. Runtime truth stays in `helm-ai-kernel`.
- [KEEP] Formula updates are blocked until `make build`, Launchpad CLI smoke, Console build, security review, and conformance evidence pass.
- [KEEP] No formula may install unverified app payloads, run host `curl | bash`, or mutate a live worktree.
- [KEEP] Formula post-install must not launch apps, provision cloud resources, write secrets, or enable live MCP servers.
- [REBUILD] If an existing formula name conflicts in the public tap, prefer fixing the tap alias/cask metadata over renaming the binary.

## Release Sequence

1. [DEFER] Complete OpenClaw local-container e2e with offline EvidencePack verification.
2. [DEFER] Complete Hermes local-container e2e or keep an explicit blocker.
3. [DEFER] Run the full kernel release gate suite.
4. [DEFER] Update `mindburnlabs/homebrew-tap/Formula/helm-ai-kernel.rb` with the verified release artifact digest.
5. [DEFER] Smoke-test `brew install mindburnlabs/tap/helm-ai-kernel` on a clean host.
6. [DEFER] Publish public website claims only after formula smoke and conformance evidence exist.
