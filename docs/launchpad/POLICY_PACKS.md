# Launchpad Policy Packs

Status: initial policy packs plus structural validation.

Policy packs live under `policies/launchpad/`. The validator parses TOML and enforces required fail-closed posture for app and substrate packs.

Required current controls:

- filesystem grants are scoped;
- network defaults are deny;
- MCP unknown servers/tools are quarantined or escalated;
- schema pinning is required;
- budget ceilings are present;
- teardown receipt is required;
- host `curl | bash`, mutable git updates, and live worktree package-manager mutation are forbidden.

The current packs are sufficient for fail-closed planning tests, not for marking apps `oss_supported`.
