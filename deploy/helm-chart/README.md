# HELM Chart

This chart deploys the retained OSS kernel from source in this repository.

## Install From Source

```bash
cd deploy/helm-chart
helm install helm-firewall .
```

Review `values.yaml` before use in a real environment.

## Notes

- The chart name is `helm-firewall` to avoid confusion with Kubernetes Helm.
- Container images default to `ghcr.io/mindburn-labs/helm-oss`.
- Persistence, ingress, and metrics options are defined in `values.yaml`.
