# Deployment

The retained deployment material in this repository is the Helm chart under `deploy/helm-chart/`.

## Helm Chart

```bash
cd deploy/helm-chart
helm dependency update
helm install helm-oss .
```

Review `values.yaml` before use in a real environment.

## Scope

Hosted demo deployment material, operator scaffolding, and monitoring bundles that were not part of the tight OSS kernel surface have been removed from this repository.
