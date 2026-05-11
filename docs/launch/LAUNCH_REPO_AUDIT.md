# HELM OSS Repository Audit (Pre-Launch)

Date: 2026-05-11
Target: `Mindburn-Labs/helm-oss`
Commit: `8a39bad` (local equivalent)

This document captures the baseline state of the repository before the Phase 0 launch-readiness remediation execution.

## 1. Branch and Build Health
*   **Branch**: `main`
*   **Go Build**: ✅ Compiles cleanly (`go build ./cmd/helm/`)
*   **Unit Tests (TEE)**: ✅ 7/7 PASS (`go test ./pkg/crypto/tee/... -count=1`)
*   **CI (GitHub Actions)**: ❌ ALL FAILING due to organization billing lock. (Accepted exception).

## 2. Commercial Leakage
*   **PR #112**: Contained commercial infrastructure references (`DO proxy`). **Remediated** via closure and replacement with `fix/oss-console-local-auth`.
*   **`wrangler.toml`**: Contained hardcoded `oss.mindburn.org`. **Remediated** to support localhost default.

## 3. Verdict Canonicalization
*   **Issue**: Legacy terminology (`DEFER`, `REQUIRE_APPROVAL`) exists in ~40+ locations across source, tests, and schemas.
*   **Action**: Must not break generated SDKs. Will remediate via canonicalization documentation and source code comments mapping these states to the canonical `ALLOW`/`DENY`/`ESCALATE` model.

## 4. Documentation & Examples
*   **Existing Examples**: 13 directories present, covering SDKs (Go, Java, Rust, Python, TS, JS), MCP client, receipt verification, and policies.
*   **Launch Demo Suite**: ❌ Missing. Requires `examples/launch/` suite.

## 5. Security & Hardware Constraints
*   **TEE Hardware**: Testing environments lack physical AMD SEV-SNP/Intel TDX hardware, resulting in expected `ErrChainUntrusted` validation failures. (Accepted exception).

## 6. Community & Ecosystem
*   **Issue Templates**: PR template, `bug_report`, `feature_request`, and `config` exist.
*   **Missing Templates**: `docs_gap`, `integration_request`, `policy_example_request` must be created.
*   **Seed Issues**: 0 open issues. Requires seeding.
*   **Homebrew**: Canonical installation path requires alignment to `mindburnlabs/tap/helm`.
