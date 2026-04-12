# HELM Governance — VS Code Extension

IDE integration for the HELM AI Execution Firewall. Provides policy editing, ProofGraph visualization, receipt inspection, and real-time compliance scoring.

## Features

### CEL Policy Syntax Highlighting
- Full Common Expression Language (CEL) syntax support
- HELM-specific variables highlighted: `trust_score`, `trust_tier`, `privilege_tier`, `compliance_score`
- Auto-completion for HELM policy functions

### ProofGraph Visualization
- Interactive DAG visualization of governance proof chains
- Color-coded by node type (INTENT, ATTESTATION, EFFECT, TRUST_EVENT, ZK_PROOF)
- Lamport ordering display

### Receipt Inspector
- Open any receipt JSON file and verify its signature inline
- View decision details, verdict, reason codes
- Navigate from receipt to related ProofGraph nodes

### Compliance Score Widget
- Real-time compliance score in the status bar
- Color-coded: green (90+), yellow (70-89), red (<70)
- Click to see per-framework breakdown (EU AI Act, HIPAA, SOX, etc.)

### Sidebar Views
- **Compliance Scores**: Live per-framework compliance status
- **Recent Receipts**: Latest governance decisions
- **Governed Agents**: Active agents and their trust scores

## Commands

| Command | Description |
|---|---|
| `HELM: Verify Receipt` | Verify the active JSON file as a receipt |
| `HELM: Show Compliance Score` | Display per-framework compliance scores |
| `HELM: Visualize ProofGraph` | Open ProofGraph DAG viewer |
| `HELM: Evaluate Policy` | Evaluate the active CEL expression |
| `HELM: Inspect Decision` | Look up a decision by ID |

## Configuration

| Setting | Default | Description |
|---|---|---|
| `helm.serverUrl` | `http://localhost:8080` | HELM server URL |
| `helm.autoVerify` | `true` | Auto-verify receipts on save |
| `helm.complianceFrameworks` | `["eu_ai_act", "hipaa", "sox", "gdpr"]` | Frameworks to track |

## Installation

```bash
# From the HELM repository
cd tools/vscode-helm
npm install
npm run compile
# Then: Extensions > Install from VSIX
```

## Prerequisites

- HELM server running (`helm server` or `helm proxy`)
- Node.js 18+
