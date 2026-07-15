---
title: Implementation Partner Handoff
last_reviewed: 2026-07-15
---

# Implementation Partner Handoff

This guide packages the local, self-hosted HELM AI Kernel v0.7.2 surface for an
implementation partner. It does not describe a hosted HELM API.

NavigoTech Innovation is an official HELM implementation partner.
Partner status does not widen runtime authority: every client action still
needs an exact routed boundary, identity scope, policy, approval path, source
read-back, and evidence contract.

## 1. Install The Pinned CLI

```bash
brew tap mindburn-labs/tap
brew update
brew install mindburn-labs/tap/helm-ai-kernel
helm-ai-kernel --version
```

The expected release for this packet is `0.7.2`. If the registry or local cache
does not return that release, stop and use the signed asset from the
[v0.7.2 release](https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.7.2).

## 2. Run A Clean Local Proof

```bash
helm-ai-kernel mcp proof --json --out ~/.helm-ai-kernel/proofs

helm-ai-kernel verify \
  --bundle ~/.helm-ai-kernel/proofs/<run-id>/evidencepacks/<run-id> \
  --profile dev-local \
  --json
```

Keep the emitted run ID, receipt paths, verification result, CLI version, and
environment in the implementation record.

## 3. Choose One Documented Surface

| Need | Surface | Current boundary |
| --- | --- | --- |
| No-key sandbox proof | Public demo HTTP or TypeScript SDK | Synthetic demo only |
| Typed application call | [SDKs](/sdks) | Local clients; auth helpers differ by language |
| Exact route contract | [HTTP API](/reference/http-api) | Filtered 16-operation public contract |
| Generated client | [OpenAPI YAML](/openapi.yaml) | Prefer when an SDK lacks required headers |
| Existing OpenAI client | [OpenAI proxy](/integrations/openai-compatible-proxy) | Local proxy mode |
| MCP configuration and authorization proof | [MCP](/integrations/mcp) | Not a general-purpose upstream proxy |

Do not present any local base URL as a hosted HELM endpoint.

## 4. Pin Runtime Mode And Base URL

| Runtime mode | Start command | Base URL |
| --- | --- | --- |
| `quickstart` | `helm-ai-kernel quickstart` | `http://127.0.0.1:7714` |
| `serve` | `helm-ai-kernel serve --policy <policy.toml>` | `http://127.0.0.1:7714` |
| `server` | `helm-ai-kernel server` | `http://127.0.0.1:8080` |
| OpenAI-compatible proxy | `helm-ai-kernel proxy --port 9090` | `http://127.0.0.1:9090/v1` |
| Selected HTTP MCP runtime | runtime-specific; see [MCP](/integrations/mcp) | `http://localhost:9100/mcp` |

The command, port, policy, and client must refer to the same runtime mode.
These loopback URLs are the only base URLs in this packet. A public docs URL,
health endpoint, or QA hostname is not a partner credential or a production API
endpoint.

## 5. Apply Route Authentication

Protected operations use the exported `HELM_ADMIN_API_KEY` as the HTTP bearer
credential.

Tenant-scoped routes also bind tenant and principal identity. When the scoped
emergency fence is enabled, the server can additionally require
`X-Helm-Workspace-ID`. Use [HTTP API](/reference/http-api) for the route class and
[SDKs](/sdks#authentication-coverage) for the per-language header gap.

If the selected SDK cannot send a required identity header, stop and use direct
HTTP or a client generated from `/openapi.yaml`. Never remove a required scope
merely to make an example run.

At v0.7.2, the handwritten TypeScript and Python clients cannot set the
principal header, and the Go client cannot set the optional workspace header.
Use those convenience clients only for routes covered by their helpers. For a
protected evaluate call, direct HTTP or a generated OpenAPI client is the
documented path until the required header helpers ship in a verified release.

## 6. Run One Protected HTTP Evaluation

Use the server-owned values supplied by the environment owner. The tenant and
principal headers are mandatory for the current evaluate contract; the
workspace header is mandatory only when the scoped emergency fence is enabled.
Start the local API server with the same server-owned values in its environment:

```bash
HELM_ADMIN_API_KEY='<environment-owned-admin-key>' \
HELM_RUNTIME_TENANT_ID='<server-owned-tenant-id>' \
HELM_RUNTIME_PRINCIPAL_ID='<server-owned-principal-id>' \
helm-ai-kernel server
```

Then, in a separate terminal, run the decision and receipt proof:

```bash
export HELM_BASE_URL=http://127.0.0.1:8080
export HELM_ADMIN_API_KEY='<environment-owned-admin-key>'
export HELM_TENANT_ID='<server-owned-tenant-id>'
export HELM_PRINCIPAL_ID='<server-owned-principal-id>'

curl --fail-with-body --silent --show-error \
  -X POST "$HELM_BASE_URL/api/v1/evaluate" \
  -H "Authorization: ${HELM_AUTH_SCHEME:-Bearer} ${HELM_ADMIN_API_KEY:?HELM_ADMIN_API_KEY is required}" \
  -H "X-Helm-Tenant-ID: $HELM_TENANT_ID" \
  -H "X-Helm-Principal-ID: $HELM_PRINCIPAL_ID" \
  -H "Idempotency-Key: navigotech-local-read-001" \
  -H 'Content-Type: application/json' \
  --data-binary "{\"principal\":\"$HELM_PRINCIPAL_ID\",\"action\":\"ticket.read\",\"resource\":\"ticket:demo-001\",\"context\":{\"effect_class\":\"read\",\"integration\":\"navigotech-local-proof\"}}"

curl --fail-with-body --silent --show-error \
  "$HELM_BASE_URL/api/v1/receipts?limit=10" \
  -H "Authorization: ${HELM_AUTH_SCHEME:-Bearer} ${HELM_ADMIN_API_KEY:?HELM_ADMIN_API_KEY is required}" \
  -H "X-Helm-Tenant-ID: $HELM_TENANT_ID" \
  -H "X-Helm-Principal-ID: $HELM_PRINCIPAL_ID"
```

Do not expect `ALLOW` merely because the request is well formed. `DENY` or
`ESCALATE` is a valid fail-closed proof when the policy, scope, approval, or
route is incomplete. Record the returned decision and receipt references before
connecting an executor. The receipt query proves boundary persistence, not
upstream dispatch. If the environment requires `X-Helm-Workspace-ID`, add the
exact server-owned value to both requests; never source it from request JSON.

## 7. Prove Dispatch And No-Dispatch

For the exact client action, record:

1. action, resource, effect class, tenant, principal, and workspace;
2. least-authority credential and expiry;
3. policy version and expected verdict;
4. named approval path for `ESCALATE`;
5. explicit executor or upstream path for `ALLOW`;
6. no-dispatch observation for `DENY` and unresolved `ESCALATE`;
7. source-system response and read-back;
8. reconciliation status and exception owner; and
9. receipt or EvidencePack plus offline verifier result.

Setup output or generated configuration is not proof that a native client loaded
HELM. Observe the configured event or call crossing the boundary.

## 8. Revoke And Hand Off

Revoke temporary MCP approval when the proof ends:

```bash
helm-ai-kernel mcp revoke \
  --server-id <server-id> \
  --reason "implementation proof complete"
```

Give the client the version pin, configuration diff, policy, credential scope,
approval path, source read-back, evidence bundle, verifier command, revocation
procedure, rollback procedure, limitations, and support owner.

## 9. Repeat Without Founder Assistance

The implementation channel is repeatable only after the partner completes the
same bounded proof for a second unrelated client without Mindburn founder or
engineering intervention. A partner announcement or generated configuration is
not a substitute for that second independent install.
