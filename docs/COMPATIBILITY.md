---
title: Compatibility
---

# Compatibility

This page describes the retained OSS compatibility surface, not every historical adapter or experimental integration that has existed in the repository.

## Supported Public Surfaces

| Surface | Status |
| --- | --- |
| Go kernel and CLI | Supported |
| OpenAI-compatible proxy | Supported |
| MCP server and bundle generation | Supported |
| Evidence export and offline verification | Supported |
| Dashboard bundle viewer | Supported |
| Go SDK | Supported |
| Python SDK | Supported |
| TypeScript SDK | Supported |
| Rust SDK | Supported |
| Java SDK | Supported |

## Source Build Expectations

The retained CI verifies:

- Go build and test for the kernel
- Python SDK tests
- TypeScript SDK tests
- Rust SDK build and test
- Java SDK build
- package-level CLI tests in `packages/mindburn-helm-cli`

## Deployment Surface

The repository keeps a Helm chart under `deploy/helm-chart/` for Kubernetes-based deployment and a local static viewer under `dashboard/`. Other hosted demo deployment material has been removed from the OSS surface.
