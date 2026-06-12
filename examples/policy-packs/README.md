# Policy Pack Examples

This directory contains runnable example policy packs for OSS evaluation. Each
`policy.*.toml` file uses the same serve-policy wrapper shape as
`release.high_risk.v3.toml` and points at a local JSON reference pack.

These files are examples only. They are not production defaults, compliance
guarantees, or complete customer policies.

## Validate

```bash
cd core/cmd/helm-ai-kernel
go test . -run TestPolicyPackExamplesLoad -count=1
```

## Packs

| Pack | Purpose |
| --- | --- |
| `policy.shell.safe-by-default.toml` | Allow read-only shell and git status actions; keep destructive shell and git operations outside the allow graph. |
| `policy.db.readonly.toml` | Allow database reads and explains; keep writes, schema changes, and destructive operations outside the allow graph. |
| `policy.cicd.approval-required.toml` | Allow CI status/log reads; keep deploys, secret changes, and workflow mutations outside the allow graph. |
| `policy.cloud.mutations.toml` | Allow cloud inventory reads; keep IAM, network, storage, and Kubernetes mutations outside the allow graph. |

Disabled actions document expected denied or approval-required classes for the
example. Active production behavior must come from a reviewed policy bundle,
runtime integration, receipt path, and EvidencePack verification command.
