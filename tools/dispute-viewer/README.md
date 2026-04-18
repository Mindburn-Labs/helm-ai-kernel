# Dispute Viewer

Offline, zero-dependency HTML viewer for HELM verification reports and conformance outputs.

## Usage

```bash
# Open in any browser — no server required
open tools/dispute-viewer/index.html
```

1. Drop a `verify.json` (from `helm verify --json-out`) or a `conform_report.json`
2. View the decision path, check results, and metadata
3. All processing happens locally — **nothing leaves your browser**

## Features

- **Decision path visualization**: Request → Policy → Decision → Receipt → Proof
- **Check-by-check breakdown**: Pass/fail with reasons for each verification check
- **Metadata display**: Bundle path, timestamp, verifier version, issue count
- **Compatible formats**: `VerifyReport` (from verifier), `ConformanceReport` (from conform)
- **Dark mode**: Minimal, auditor-focused interface
