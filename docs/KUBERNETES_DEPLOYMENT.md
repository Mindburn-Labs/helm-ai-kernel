---
title: Kubernetes Deployment
last_reviewed: 2026-09-26
---

# Kubernetes Deployment

This page documents the repository-owned HELM AI Kernel chart for self-hosted
evaluation and staging smoke tests. It is not a managed-service runbook and it
does not publish tenant, control-plane, signing, or operator-secret procedures.

## Audience

Kubernetes operators who need to render the chart, understand the Kernel
runtime boundary, and run a staging smoke path for health, receipts, and
evidence persistence.

## Outcome

After this page you should be able to lint the chart, render manifests, install
a staging release with local test material, and verify that health and receipt
persistence behave as expected.

## Source Truth

The chart source is `deploy/helm-chart`. Runtime container wiring is in
`deploy/helm-chart/templates/deployment.yaml`; values are in
`deploy/helm-chart/values.yaml`.

## Validate The Chart

```bash
make helm-chart-smoke
helm lint deploy/helm-chart
helm template helm-ai-kernel deploy/helm-chart
```

Expected output: lint succeeds, `helm template` emits Deployment, Service,
ConfigMap, Secret, PVC, and optional ServiceMonitor manifests, and
`make helm-chart-smoke` completes without rendering a protected chart that lacks
required local test material.

## Policy Authority Boundary

Kubernetes objects do not become HELM execution authority. The chart deploys the
runtime and configures a `policy.source` backend. The runtime reconciler owns
policy truth: it reads the active head, loads the canonical bundle, verifies the
expected hash and signature/provenance, compiles a snapshot, validates it, then
atomically swaps the per-scope `EffectivePolicySnapshot`.

## Staging Install Skeleton

Use existing Kubernetes Secrets for any sensitive values. Do not put real keys
in shell history or public issues.

```bash
kubectl create secret generic helm-auth \
  --from-literal=HELM_ADMIN_API_KEY='<local-test-admin-key>' \
  --from-literal=HELM_SERVICE_API_KEY='<local-test-service-key>'

helm upgrade --install helm-ai-kernel deploy/helm-chart \
  --set helm.auth.existingSecret=helm-auth \
  --set persistence.enabled=true
```

## Values That Control Runtime Behavior

| Value | Default | Source-backed behavior |
| --- | --- | --- |
| `image.repository` | `ghcr.io/mindburn-labs/helm-ai-kernel` | Container image used by the Deployment. |
| `image.tag` | chart `appVersion` | The source target is `v0.9.0` from `Chart.yaml`. It is not a published image until the tag-driven release workflow publishes and verifies it; use only a source-owned image tag (or local override) you can verify. |
| `helm.bindAddr` | `0.0.0.0` | Required because the pod must bind beyond loopback. |
| `service.port` | `8080` | Runtime HTTP port passed to `helm-ai-kernel serve --port`. |
| `service.healthPort` | `8081` | Health probe port via `HELM_HEALTH_PORT`. |
| `helm.dataDir` | `/data` | Mounted from the chart PVC or `emptyDir`. |
| `helm.proxy.enabled` | `true` | Sets `HELM_ENABLE_OPENAI_PROXY=1` and `HELM_UPSTREAM_URL`. |
| `helm.storage.type` | `sqlite` | Uses local SQLite unless another supported store is configured. |
| `persistence.enabled` | `true` | Creates or reuses a PVC for receipts, state, and artifacts. |
| `ingress.enabled` | `false` | Optional ingress; provide TLS and ingress class explicitly. |
| `helm.tls.existingSecret` | empty | `kubernetes.io/tls` Secret whose `tls.crt` and `tls.key` serve the API listener over HTTPS (`HELM_TLS_CERT_FILE`, `HELM_TLS_KEY_FILE`). Empty keeps plain HTTP. |
| `helm.tls.clientAuth` | empty | `require` or `verify-if-given` client certificates against the Secret's `ca.crt` (`HELM_TLS_CLIENT_AUTH`, `HELM_TLS_CLIENT_CA_FILE`). Needs `helm.tls.existingSecret`. |
| `helm.auth.organizationRuntimeAPIKeySecretKey` | `HELM_ORGANIZATION_RUNTIME_API_KEY` | Key read from `helm.auth.existingSecret` into `HELM_ORGANIZATION_RUNTIME_API_KEY`, as an optional key. Empty stops reading it. |

## Native TLS For In-Cluster Callers

The Control Plane reaches the Kernel over HTTPS inside the cluster without an
Ingress. Issue a certificate for the Kernel Service name, for example with a
cert-manager `Certificate` whose `secretName` is `helm-kernel-tls`, then:

```bash
helm upgrade --install helm-ai-kernel deploy/helm-chart \
  --set helm.auth.existingSecret=helm-auth \
  --set helm.tls.existingSecret=helm-kernel-tls
```

The Secret is mounted whole at `/var/run/secrets/helm-tls`, so a rotated
certificate reaches the running Kernel without a restart. The liveness and
readiness probes use the plain-HTTP health port and do not change. The chart
refuses TLS together with the config-reloader sidecar, which wakes the API
listener over plain HTTP. An Ingress in front of a TLS listener needs its
controller's HTTPS-backend setting.

Add `--set helm.tls.clientAuth=require` to demand a client certificate signed
by the Secret's `ca.crt`. Put `HELM_ORGANIZATION_RUNTIME_API_KEY` in the
`helm-auth` Secret to open the organization-runtime route to the Control
Plane. The Control Plane pins the receipt signer from
`GET /api/v1/receipt-keyring`; see [HTTP API](reference/http-api.md#receipt-keyring).

## Effect gateway (helm-gateway)

The release image carries `/usr/local/bin/helm-gateway` next to
`helm-ai-kernel`, so both run from one tag under one cosign identity.
`gateway.enabled=true` deploys `helm-gateway serve` from that image; it is off
by default and the default render does not change. The value table is in the
[chart README](../deploy/helm-chart/README.md#effect-gateway-gateway).

What renders:

- a Deployment running `helm-gateway serve`, with its own ServiceAccount and
  no Kubernetes API token, the kernel's Pod and container security contexts,
  and probes on the health port (`/healthz`; `/readyz` answers only when the
  database schema is at the binary's head version);
- a Service on 8443 (TLS, or mutual TLS with `gateway.tls.clientAuth`);
- a NetworkPolicy, described below;
- a pre-install/pre-upgrade hook Job that migrates the database before the new
  Pods start.

Required values fail the render with a message naming them:
`gateway.tls.existingSecret` (or `gateway.tls.devInsecureLoopback=true`
outside production), the four `gateway.controlPlaneIdentity.*` values,
`gateway.database.existingSecret`, and, with the NetworkPolicy on, a Control
Plane selector and `gateway.networkPolicy.database.to`.

### Database roles: owner and runtime

ADR-0004 separates the role that owns the schema from the role that serves.
`helm-gateway migrate` creates the tables; whoever runs it owns them, and a
table owner can turn row-level security off. So migrate runs as the owner and
`serve` runs as a role with DML grants only:

| Role | Attributes | Does |
| --- | --- | --- |
| `helm_owner` | NOLOGIN | Owns the `helm_gateway` schema and every table. The migrate and grant steps `SET ROLE` to it through `PGOPTIONS`. |
| `helm_gateway` | LOGIN | The runtime DSN. `SELECT, INSERT, UPDATE` on the `authority_*` tables, `SELECT, INSERT` on `authority_postings`, `DELETE` added on `authority_token_replay`, `SELECT` on `gateway_schema_migrations`. |

Neither role has SUPERUSER, BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION,
and the runtime role must not be a member of the owner role.

With `gateway.database.bootstrap.enabled=true` the hook Job runs, in order:

1. `files/gateway-db/001_roles.sql` with `psql` as the administrator from
   `gateway.database.bootstrap.existingSecret`. It creates or converges both
   roles, grants the administrator membership in the owner, creates the schema
   owned by the owner, sets the runtime role's `search_path`, and sets its
   password when the Secret has `HELM_GATEWAY_ROLE_PASSWORD`;
2. `helm-gateway migrate` with the administrator DSN and
   `PGOPTIONS=-c role=helm_owner -c search_path=helm_gateway`, so every table
   is created by the owner;
3. `files/gateway-db/002_grants.sql` as the owner. It revokes and re-grants the
   runtime set in one transaction and fails on a table it has no rule for.

Each step is idempotent. The administrator may be a superuser, or a role with
CREATEROLE and CREATE on the database, as on a managed database. A drifted
attribute that the administrator is not allowed to reset, such as BYPASSRLS
without holding it, fails the Job before migrate runs.
`core/pkg/gateway/admission/chart_roles_postgres_test.go` runs these files
against PostgreSQL 16 in both administrator modes, twice each, and checks the
role attributes, ownership and exact grants. It then serves admission as the
runtime role.

Without the bootstrap, the hook runs `helm-gateway migrate` with
`gateway.database.migrate.existingSecret`, the owner's DSN. The operator
creates the roles and grants. If that value is empty, migrate runs with the
runtime DSN and the serving role owns the tables. That is acceptable for
development only, and `helm.production=true` refuses to render it.

### Network policy

- **Ingress:** TCP 8443, only from the peers selected by
  `gateway.networkPolicy.controlPlane` (a namespace selector, a Pod selector,
  or both combined). The health port has no ingress rule; kubelet probes come
  from the node.
- **Egress:**
  - DNS on UDP and TCP 53 to `gateway.networkPolicy.dns.to`;
  - the database on `gateway.networkPolicy.database.port` to
    `gateway.networkPolicy.database.to`;
  - TCP 443 to any address.

The gateway calls `api.github.com` and fetches the JWKS on 443. A
NetworkPolicy cannot name a host, so this rule is port-only and does not stop
the Pod from reaching other hosts on 443. For a JWKS endpoint on another port,
add a rule under `gateway.networkPolicy.extraEgress`. Enforcement also depends
on a CNI that implements NetworkPolicy.

### GitHub App credentials

`gateway.github.existingSecret` is mounted into the gateway Pod and no other
Pod (R8), as:

- `/var/run/secrets/helm-gateway-github/app-id`
  (`HELM_GATEWAY_GITHUB_APP_ID_FILE`);
- `/var/run/secrets/helm-gateway-github/private-key.pem`
  (`HELM_GATEWAY_GITHUB_APP_PRIVATE_KEY_FILE`).

`gateway.github.installationsFile` is rendered into a ConfigMap and mounted as
`/etc/helm-gateway/github/installations.json`
(`HELM_GATEWAY_GITHUB_INSTALLATIONS_FILE`). The current binary does not read
these files yet; the connection custody of HELM-751 slice 3 will read them at
these paths.

### Example (qa)

```bash
helm upgrade --install helm-ai-kernel deploy/helm-chart \
  --set gateway.enabled=true \
  --set gateway.tls.existingSecret=helm-gateway-tls \
  --set gateway.controlPlaneIdentity.jwksURL=https://cp.example.internal/.well-known/jwks.json \
  --set gateway.controlPlaneIdentity.issuer=https://cp.example.internal \
  --set gateway.controlPlaneIdentity.audience=helm-gateway:qa \
  --set gateway.controlPlaneIdentity.actor=spiffe://helm/control-plane \
  --set gateway.database.existingSecret=helm-gateway-db \
  --set gateway.database.bootstrap.enabled=true \
  --set gateway.database.bootstrap.existingSecret=helm-gateway-db-admin \
  --set gateway.networkPolicy.controlPlane.namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=helm-control-plane \
  --set gateway.networkPolicy.database.to[0].ipBlock.cidr=10.0.0.10/32
```

For development without a certificate, set
`gateway.tls.devInsecureLoopback=true` and reach the API with
`kubectl port-forward deploy/helm-ai-kernel-gateway 8443:8443`.

## Smoke Checks

```bash
kubectl rollout status deploy/helm-ai-kernel
kubectl port-forward svc/helm-ai-kernel 8080:8080
curl -fsS http://127.0.0.1:8080/health
```

Then run a governed request through the public API or OpenAI-compatible proxy
and verify that receipts persist after pod restart when `persistence.enabled`
is true.

## Not Covered

Managed deployments, tenant migrations, SSO, SIEM, retention controls, private
control-plane wiring, and operator key ceremonies belong outside the anonymous
public Kernel docs.
