# Security Policy

## Reporting a Vulnerability

**DO NOT** open a public issue for security vulnerabilities.

Email: **security@mindburn.org**

You will receive acknowledgment within 48 hours and a detailed response within 7 days.

## Security Model

HELM is a **fail-closed execution kernel**. The security model assumes:

- **The model is untrusted.** Models propose; the kernel disposes.
- **Tool inputs are untrusted.** Every tool call is schema-validated, canonicalized (JCS/RFC 8785), and hash-bound before execution.
- **Tool outputs are untrusted.** Connector outputs are validated against pinned schemas. Contract drift is a hard error.
- **Untrusted code is sandboxed.** WASI execution has deny-by-default capabilities (no FS, no network) with gas, time, and memory budgets.
- **History is immutable.** Every execution produces a signed receipt linked in a ProofGraph DAG with Lamport clocks.

## What HELM Stops

| Attack | Defense |
|--------|---------|
| Prompt injection → unauthorized tool call | Guardian policy engine blocks undeclared tools |
| Argument tampering | JCS canonicalization + SHA-256 hash binding |
| Output spoofing by malicious connector | Pinned output schema validation (fail-closed) |
| Resource exhaustion via WASM | Gas/time/memory budgets with deterministic traps |
| Receipt forgery | Ed25519 signatures on canonical payloads |
| Replay attacks | Lamport clock monotonicity + causal PrevHash chain |
| Approval bypass | Timelock + deliberate confirmation hash + domain separation |

## What HELM Does NOT Stop

- Prompt injection that stays within the text/conversation domain (HELM governs execution, not generation)
- Vulnerabilities in upstream LLM providers
- Side-channel attacks on the host OS
- Social engineering of human approvers

## TCB (Trusted Computing Base)

The kernel TCB is 8 packages. See `docs/TCB_POLICY.md`.

## Supported Versions

Security fixes are backported to the current release and the immediately preceding minor.

| Version | Supported | Notes |
|---------|-----------|-------|
| 0.4.x   | ✅        | Current (Phase 0–4 AGT-response) |
| 0.3.x   | ✅        | Previous minor; fixes backported through 2026-10 |
| 0.2.x   | ❌        | End of life |
| 0.1.x   | ❌        | End of life |

## Cryptographic Signing and Provenance

Every released binary is:

- **Signed** with [Sigstore cosign](https://docs.sigstore.dev/cosign/signing/overview/) using GitHub Actions OIDC identity (no long-lived keys).
- **Attested** with [SLSA Level 3 provenance](https://slsa.dev/) on the Sigstore Rekor public transparency log.
- **Inventoried** with a [CycloneDX 1.5 SBOM](https://cyclonedx.org/) attached as a release asset.
- **Reproducible** via hermetic builds with pinned dependencies.

Verify a release binary:

```bash
# Verify cosign signature
cosign verify-blob \
  --certificate-identity-regexp="^https://github.com/Mindburn-Labs/helm-oss" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --signature helm-linux-amd64.tar.gz.sig \
  helm-linux-amd64.tar.gz

# Verify SLSA provenance
slsa-verifier verify-artifact \
  --provenance-path helm.intoto.jsonl \
  --source-uri github.com/Mindburn-Labs/helm-oss \
  helm-linux-amd64.tar.gz
```

## Vulnerability Scanning

- [OpenSSF Scorecard](https://securityscorecards.dev/) weekly via `.github/workflows/scorecard.yml`.
- Dependabot enabled across all ecosystems (Go modules, pip, npm, cargo, Maven).
- Fuzz harness nightly (`.github/workflows/fuzz.yml`) — 18 targets across canonicalization, crypto, kernel, guardian, contracts, threat scanner, compliance, saga, a2a.
- Chaos drill weekly (`.github/workflows/chaos-drill.yml`) — 6 fail-closed invariant scenarios co-located in `core/pkg/*/chaos_test.go`.
- Apalache TLA+ model-check nightly (`.github/workflows/apalache.yml`) — 6 specifications.

## Responsible Disclosure Policy

- **In-scope**: this repository, its published SDK packages (`pip`, `npm`, `crates.io`, Maven Central), release binaries on GitHub Releases and `ghcr.io/mindburn-labs/helm-oss`, and the `try.mindburn.org` dashboard.
- **Out-of-scope**: the commercial `helm/` repository and hosted services, customer deployments, third-party integrations.
- **Safe-harbor**: good-faith researchers following this policy will not be pursued under DMCA, CFAA, or equivalent laws. No authorization for destructive testing of production infrastructure.
- **Hall of fame**: with researcher consent, findings are credited at `trust.mindburn.org/hall-of-fame`.
- **Bug bounty**: $50–$10,000 per finding by severity, hosted on HackerOne (in-scope only).

## Disclosure Timeline

We follow coordinated disclosure with a 90-day window. CVEs are assigned via GitHub Security Advisories, published after the fix ships plus a 14-day embargo for coordinated patching.

## Security Contact

- **Email**: `security@mindburn.org`
- **PGP key**: published at `https://mindburn.org/.well-known/security.asc`
- **Ack SLA**: 48 hours
- **Response SLA**: 7 business days for severity classification; 30 days for patch or mitigation
- **`security.txt`**: served at `https://try.mindburn.org/.well-known/security.txt` per RFC 9116
