# HELM Firewall Kubernetes Helm Chart

Kubernetes Helm chart for deploying [HELM](https://github.com/Mindburn-Labs/helm-oss) -- the fail-closed AI execution firewall with cryptographic governance proofs.

> **Note:** The chart is named `helm-firewall` to avoid confusion with Kubernetes Helm itself.

## Prerequisites

- Kubernetes 1.26+
- Helm 3.12+

## Installation

### From repository

```bash
# Add the Mindburn chart repository
helm repo add mindburn https://charts.mindburn.org
helm repo update

# Install with defaults (SQLite storage, Ed25519 signing)
helm install helm-firewall mindburn/helm-firewall

# Install into a specific namespace
helm install helm-firewall mindburn/helm-firewall --namespace helm-system --create-namespace
```

### From source

```bash
cd deploy/helm-chart
helm install helm-firewall .
```

## Configuration

### Quick examples

```bash
# Install with PostgreSQL backend
helm install helm-firewall mindburn/helm-firewall \
  --set helm.storage.type=postgres \
  --set helm.storage.postgres.host=my-postgres \
  --set helm.storage.postgres.password=secret

# Install with custom upstream LLM provider
helm install helm-firewall mindburn/helm-firewall \
  --set helm.proxy.upstream=https://api.anthropic.com/v1

# Install with existing signing key secret
helm install helm-firewall mindburn/helm-firewall \
  --set helm.signing.existingSecret=my-signing-key

# Install with Ingress enabled
helm install helm-firewall mindburn/helm-firewall \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set ingress.hosts[0].host=helm.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix

# Install with Prometheus ServiceMonitor
helm install helm-firewall mindburn/helm-firewall \
  --set helm.metrics.serviceMonitor.enabled=true
```

### Parameters

#### General

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Container image repository | `ghcr.io/mindburn-labs/helm-oss` |
| `image.tag` | Container image tag (defaults to `appVersion`) | `""` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `nameOverride` | Override chart name | `""` |
| `fullnameOverride` | Override full release name | `""` |

#### HELM Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `helm.proxy.enabled` | Enable LLM proxy mode | `true` |
| `helm.proxy.upstream` | Upstream LLM provider URL | `https://api.openai.com/v1` |
| `helm.region` | Region identifier | `us` |
| `helm.demoMode` | Enable demo mode (ephemeral keys, no real connectors) | `false` |
| `helm.signing.algorithm` | Signing algorithm (`ed25519` or `ml-dsa-65`) | `ed25519` |
| `helm.signing.key` | Signing key value | `""` |
| `helm.signing.existingSecret` | Use existing secret for signing key | `""` |
| `helm.storage.type` | Storage backend (`sqlite` or `postgres`) | `sqlite` |
| `helm.storage.sqlite.path` | SQLite database path | `/data/helm.db` |
| `helm.storage.postgres.host` | PostgreSQL host | `""` |
| `helm.storage.postgres.port` | PostgreSQL port | `5432` |
| `helm.storage.postgres.database` | PostgreSQL database name | `helm` |
| `helm.storage.postgres.user` | PostgreSQL user | `helm` |
| `helm.storage.postgres.password` | PostgreSQL password | `""` |
| `helm.storage.postgres.sslMode` | PostgreSQL SSL mode | `disable` |
| `helm.storage.postgres.existingSecret` | Existing secret with `DATABASE_URL` | `""` |
| `helm.policy.configMap` | ConfigMap with policy files to mount | `""` |

#### Observability

| Parameter | Description | Default |
|-----------|-------------|---------|
| `helm.metrics.enabled` | Expose metrics port | `true` |
| `helm.metrics.serviceMonitor.enabled` | Create Prometheus ServiceMonitor | `false` |
| `helm.metrics.serviceMonitor.interval` | Scrape interval | `30s` |
| `helm.metrics.serviceMonitor.labels` | Additional labels for ServiceMonitor | `{}` |

#### Persistence

| Parameter | Description | Default |
|-----------|-------------|---------|
| `persistence.enabled` | Enable PVC for SQLite storage | `true` |
| `persistence.storageClass` | Storage class | `""` |
| `persistence.accessModes` | PVC access modes | `[ReadWriteOnce]` |
| `persistence.size` | PVC size | `1Gi` |
| `persistence.existingClaim` | Use existing PVC | `""` |

#### Networking

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port (API) | `8080` |
| `service.metricsPort` | Service port (metrics) | `9090` |
| `ingress.enabled` | Enable Ingress | `false` |
| `ingress.className` | Ingress class name | `""` |
| `ingress.hosts` | Ingress hosts configuration | see `values.yaml` |
| `ingress.tls` | Ingress TLS configuration | `[]` |

#### Security

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create ServiceAccount | `true` |
| `serviceAccount.annotations` | ServiceAccount annotations | `{}` |
| `podSecurityContext.runAsNonRoot` | Run as non-root | `true` |
| `podSecurityContext.runAsUser` | Pod user ID | `65534` |
| `securityContext.readOnlyRootFilesystem` | Read-only root filesystem | `true` |
| `securityContext.allowPrivilegeEscalation` | Disallow privilege escalation | `false` |

## Security considerations

- **Signing keys**: For production, always use `helm.signing.existingSecret` to reference a pre-created Kubernetes Secret rather than passing the key via `--set`. If neither is provided, the chart generates a random key (not suitable for production).
- **Database credentials**: Use `helm.storage.postgres.existingSecret` to inject `DATABASE_URL` from a pre-created Secret. Avoid passing passwords via `--set` in production.
- **Pod security**: The chart runs as non-root (UID 65534), with a read-only root filesystem and all capabilities dropped. This matches the distroless base image used by HELM.
- **Fail-closed**: HELM is fail-closed by design. If the firewall cannot verify a request, it denies it.

## Upgrading

```bash
helm upgrade helm-firewall mindburn/helm-firewall --reuse-values
```

## Uninstalling

```bash
helm uninstall helm-firewall
```

Note: PersistentVolumeClaims are not deleted automatically. To fully clean up:

```bash
kubectl delete pvc -l app.kubernetes.io/instance=helm-firewall
```
