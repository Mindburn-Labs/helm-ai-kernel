---
title: Quickstart
---

# Quickstart

This walkthrough builds the kernel locally, runs a deterministic demo, exports an evidence bundle, and verifies it offline.

## 1. Build

```bash
git clone https://github.com/Mindburn-Labs/helm-oss.git
cd helm-oss
make build
```

The build outputs `bin/helm`.

## 2. Initialize Local State

```bash
./bin/helm onboard --yes
```

This prepares the local data directories and signing material used by the demo and verification flow.

## 3. Run the Demo

```bash
./bin/helm demo organization --template starter --provider mock
```

The mock provider path is the lowest-friction way to exercise the policy, receipt, and evidence paths without external service credentials.

## 4. Export an Evidence Bundle

```bash
./bin/helm export --evidence ./data/evidence --out evidence.tar
```

## 5. Verify Offline

```bash
./bin/helm verify --bundle evidence.tar
```

## 6. Open the Viewer

Serve the static viewer locally:

```bash
cd dashboard
python3 -m http.server 8000
```

Then open `http://localhost:8000/` and drop the exported bundle into the page.

## 7. Run the Validation Targets

```bash
make test
make test-all
make crucible
```

These targets cover the kernel package tests, SDK validation, fixture verification, and the retained use-case test runner.

## Existing Client Integration

To put HELM in front of an existing OpenAI-compatible client:

```bash
./bin/helm proxy --upstream https://api.openai.com/v1
```

Then update the client base URL to `http://localhost:8080/v1`.
