# HELM Governance Scan Action

Comprehensive governance security scanning for AI agent projects. Validates OWASP Agentic Top 10 compliance, policy integrity, threat detection coverage, and evidence chain verification.

## Quick Start

```yaml
- uses: Mindburn-Labs/helm-oss/.github/actions/governance-scan@main
  with:
    command: governance-verify
```

## Commands

| Command | Description |
|---------|-------------|
| `governance-verify` | OWASP Agentic Top 10 compliance check (default) |
| `security-scan` | Threat detection and policy validation |
| `policy-evaluate` | Evaluate policies against a context |
| `evidence-verify` | Verify evidence pack integrity |
| `full` | Run all checks |

## Usage Examples

### OWASP Compliance Check (CI Gate)

```yaml
name: Governance Gate
on: [pull_request]

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Mindburn-Labs/helm-oss/.github/actions/governance-scan@main
        id: scan
        with:
          command: governance-verify
          output-format: json
      - run: echo "Passed ${{ steps.scan.outputs.controls-passed }}/${{ steps.scan.outputs.controls-total }}"
```

### Security Scan

```yaml
- uses: Mindburn-Labs/helm-oss/.github/actions/governance-scan@main
  with:
    command: security-scan
    fail-on-warning: 'true'
```

### Policy Evaluation

```yaml
- uses: Mindburn-Labs/helm-oss/.github/actions/governance-scan@main
  with:
    command: policy-evaluate
    policy-path: ./policies/
    context-json: '{"agent_id": "test-agent", "action": "read_file"}'
```

### Evidence Verification

```yaml
- uses: Mindburn-Labs/helm-oss/.github/actions/governance-scan@main
  with:
    command: evidence-verify
    evidence-path: ./artifacts/evidence-pack/
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `command` | No | `governance-verify` | Scan command to run |
| `policy-path` | No | | Path to policy bundle (for `policy-evaluate`) |
| `context-json` | No | `{}` | JSON context for policy evaluation |
| `evidence-path` | No | | Path to evidence pack (for `evidence-verify`) |
| `conformance-level` | No | `L2` | Conformance level: L1, L2, or L3 |
| `output-format` | No | `text` | Output format: text, json, or badge |
| `fail-on-warning` | No | `false` | Fail the step on warnings |
| `helm-version` | No | `latest` | HELM version to install |
| `go-version` | No | `1.25.0` | Go version for building HELM |

## Outputs

| Output | Description |
|--------|-------------|
| `status` | Overall status: `pass`, `warn`, or `fail` |
| `controls-passed` | Number of controls passed |
| `controls-total` | Total controls checked |
| `violations` | JSON array of violations |
| `output` | Full scan output |
| `evidence-hash` | SHA-256 hash of scan evidence |

## OWASP Agentic Top 10 Controls

The `governance-verify` command checks for all 10 OWASP Agentic Security risks plus bonus hardening checks:

| Control | Check |
|---------|-------|
| ASI-01 | Prompt injection detection (`threatscan/`) |
| ASI-02 | Tool poisoning / rug-pull detection (`mcp/rugpull.go`) |
| ASI-03 | Permission scope enforcement (`effects/` permits) |
| ASI-04 | Permission validation (`guardian/` pipeline) |
| ASI-05 | Output quarantine (`Guardian.EvaluateOutput()`) |
| ASI-06 | Resource budget gates |
| ASI-07 | Cascade protection (circuit breakers) |
| ASI-08 | Egress firewall (fail-closed) |
| ASI-09 | MCP governance interceptor |
| ASI-10 | Evidence packs and ProofGraph |
| Bonus | TLA+ formal verification |
| Bonus | Post-quantum crypto (ML-DSA-65) |
| Bonus | Reversibility classification |
| Bonus | OpenTelemetry integration |
| Bonus | CloudEvents SIEM export |
