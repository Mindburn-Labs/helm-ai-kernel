# HELM Kubernetes Operator

Cloud-native operator for deploying and managing HELM governance in Kubernetes clusters.

## CRDs

### PolicyBundle
Declares a signed, content-addressed policy bundle. The operator controller reconciles this CR to ensure the Guardian instance has the correct policy loaded.

```yaml
apiVersion: helm.mindburn.ai/v1alpha1
kind: PolicyBundle
metadata:
  name: production-policies
spec:
  bundleId: "bundle-prod-v3"
  version: 3
  contentHash: "sha256:a1b2c3d4..."
  signature: "sha256:f0e1d2c3..."
  signerKeyId: "hsm-prod-key-003"
  conformanceLevel: "L3"
```

### GuardianSidecar
Annotation-driven sidecar injection for governed workloads. Injects the Guardian container into matching pods.

```yaml
apiVersion: helm.mindburn.ai/v1alpha1
kind: GuardianSidecar
metadata:
  name: default-guardian
spec:
  image: "ghcr.io/mindburn-labs/helm-guardian:v0.2.0"
  conformanceLevel: "L2"
  policyBundleRef: "production-policies"
  failClosed: true
```

## Quick Start

```bash
# Install CRDs
kubectl apply -f config/crd/helm-crds.yaml

# Verify CRDs registered
kubectl get crd | grep helm.mindburn.ai

# Apply sample resources
kubectl apply -f config/samples/example.yaml

# Check status
kubectl get policybundles
kubectl get guardiansidecars
```

## Architecture

```
┌─────────────────────────────────────────┐
│  K8s Control Plane                      │
│  ┌───────────────────────────────────┐  │
│  │ HELM Operator                     │  │
│  │ ┌─────────────┐ ┌──────────────┐  │  │
│  │ │ PolicyBundle │ │ GuardianSider│  │  │
│  │ │ Controller   │ │ car Injector │  │  │
│  │ └──────┬──────┘ └──────┬───────┘  │  │
│  │        │               │          │  │
│  │  ┌─────▼─────┐  ┌─────▼──────┐   │  │
│  │  │  Bundle    │  │  Webhook   │   │  │
│  │  │  Fetcher   │  │ (Mutating) │   │  │
│  │  └───────────┘  └────────────┘   │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │ Governed Pods                     │  │
│  │ ┌─────────┐ ┌───────────────┐    │  │
│  │ │ App     │ │ Guardian      │    │  │
│  │ │ Container│ │ Sidecar      │    │  │
│  │ └─────────┘ └───────────────┘    │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

## Conformance Admission Webhook

The operator includes a validating admission webhook that:
1. Checks deployments for `helm.mindburn.ai/conformance-level` annotation
2. Rejects deployments that don't meet the minimum conformance level
3. Validates PolicyBundle references exist and are in `Active` phase

## Status

> **Note**: This is a scaffold providing CRD definitions, type definitions, and architectural specification. Full production deployment requires kubebuilder/operator-sdk code generation.
