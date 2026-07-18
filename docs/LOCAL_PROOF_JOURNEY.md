---
title: Local Proof Journey
last_reviewed: 2026-07-18
---

# Local Proof Journey

Use this only for the local Kernel proof path. It is not a hosted-service or
runtime-availability statement.

1. [Install the Kernel](QUICKSTART.md).
2. [Write a policy](architecture/policy-languages.md), then review how
   [DENY and ESCALATE](HOW_HELM_WORKS.md#verdicts) stop an action before it
   runs.
3. [Run the proof loop](PROOF_LOOP.md) through the configured local boundary.
4. [Inspect the receipt](VERIFICATION.md#inspect-local-receipts) for the
   decision, reason, and approval context.
5. [Verify the EvidencePack](guides/export-verify-evidencepacks.md) offline.

An `ESCALATE` result does not continue the original action. Use the scoped
approval path, then rerun the action so the Kernel evaluates it again.
