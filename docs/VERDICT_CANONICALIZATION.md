# HELM Verdict Canonicalization

HELM operates on a strict, three-verdict execution model, documented in the Unified Canonical Standard (UCS) v1.3:

1.  **`ALLOW`**: The action is permitted and signed.
2.  **`DENY`**: The action is blocked, and execution must halt.
3.  **`ESCALATE`**: The system cannot make a deterministic `ALLOW` or `DENY` decision autonomously; human intervention or a higher-tier policy override is required.

## Legacy Terminology

In earlier iterations of the HELM engine, the terms `DEFER`, `REQUIRE_APPROVAL`, and `APPROVAL_REQUIRED` were used to represent the state where a decision could not be reached autonomously.

To maintain backward compatibility with existing wire-format schemas, generated SDKs, and stored policies, these terms may still appear in the `helm-ai-kernel` repository's source code, tests, and JSON schemas.

**Canonical Mapping:**

*   Any internal engine state returning `DEFER` must be interpreted by integrations as the canonical `ESCALATE` verdict.
*   Any schema field or SDK constant named `REQUIRE_APPROVAL` or `APPROVAL_REQUIRED` maps directly to the `ESCALATE` workflow.

New documentation, public APIs, and user-facing Console interfaces must exclusively use the `ALLOW`, `DENY`, and `ESCALATE` terminology.
