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
- fixture root verification through the Go verifier

## Deployment Surface

The repository keeps a Helm chart under `deploy/helm-chart/` for Kubernetes-based deployment. Interactive clients, static viewers, Node CLI wrappers, and generated browser-rendered reports are outside the retained OSS compatibility surface.
