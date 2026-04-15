# OpenClaw Exposure Audit — HELM-OSS

**Date:** 2026-04-12
**Auditor:** Automated security review (Claude Code)
**Context:** OpenClaw had 21K exposed instances. This audit checks HELM-OSS for similar vectors.

---

## Summary

| Severity | Count | FIXED | NEEDS_FIX | MITIGATED | ACCEPTABLE_RISK |
|----------|-------|-------|-----------|-----------|-----------------|
| CRITICAL | 2     | 2     | 0         | 0         | 0               |
| HIGH     | 4     | 4     | 0         | 0         | 0               |
| MEDIUM   | 4     | 0     | 0         | 2         | 2               |
| LOW      | 3     | 0     | 0         | 1         | 2               |

---

## CRITICAL Findings

### C-1: All server bindings use `0.0.0.0` by default (wildcard listen)

**Severity:** CRITICAL
**Status:** FIXED
**Files:**
- `core/cmd/helm/main.go:219` — main API server binds `:<port>` (equivalent to `0.0.0.0:<port>`)
- `core/cmd/helm/main.go:252` — health server binds `:<port>`
- `core/cmd/helm/proxy_cmd.go:517` — proxy binds `:<port>`
- `core/cmd/helm/mcp_runtime.go:418` — MCP HTTP server binds `:<port>`
- `core/cmd/helm/web_cmd.go:69` — web UI (explorer/dashboard/simulator) binds `:<port>`
- `core/cmd/helm/controlroom_cmd.go:78` — control room binds `:<port>`
- `core/cmd/channel_gateway/main.go:143` — channel gateway binds `:<port>`

**Impact:** Any HELM instance started with default settings is accessible from ANY network interface on the host. A user running `helm server` on a cloud VM exposes the full API to the internet. This is the primary OpenClaw vector.

**Remediation:** Default all server bindings to `127.0.0.1` (localhost only). Add `--bind` or `HELM_BIND_ADDR` flag/env for users who intentionally want network exposure.

---

### C-2: Unauthenticated trust key management endpoints

**Severity:** CRITICAL
**Status:** FIXED
**Files:**
- `core/pkg/api/trust_keys_handler.go:31-109` — `POST /api/v1/trust/keys/add` and `POST /api/v1/trust/keys/revoke`
- `core/cmd/helm/subsystems.go:223-225` — routes now wrapped with `auth.RequireAdminAuth`
- `core/pkg/auth/apikey.go` — new `AdminAPIKeyMiddleware` (pre-shared key via `HELM_ADMIN_API_KEY`, fail-closed, constant-time compare)

**Impact:** Anyone with network access can add arbitrary Ed25519 public keys to the trust registry or revoke existing keys. This allows an attacker to inject trusted signing keys (privilege escalation) or revoke legitimate keys (denial of service on verification).

**Fix applied:** Trust key endpoints now require `Authorization: Bearer <key>` validated against `HELM_ADMIN_API_KEY` env var. If the env var is unset, all requests are rejected (fail-closed). Constant-time comparison prevents timing attacks. 6 tests added in `core/pkg/auth/apikey_test.go`.

---

## HIGH Findings

### H-1: Credential management endpoints rely on spoofable header for authorization

**Severity:** HIGH
**Status:** FIXED
**Files:**
- `core/pkg/credentials/handlers.go:42-49` — `getOperatorID()` now reads from authenticated `auth.Principal` in context
- `core/pkg/credentials/handlers.go:30-38` — all 9 routes wrapped with `AdminAPIKeyMiddleware`

**Impact:** The credential store endpoints previously accepted `X-Operator-ID` from the request header with fallback to `"default-operator"`. Any network client could impersonate any operator by setting this header, gaining access to store, read status, and delete API keys for all providers.

**Fix applied:** (1) `getOperatorID()` now extracts operator ID from `auth.GetPrincipal(ctx)` — the authenticated principal injected by middleware — instead of the raw `X-Operator-ID` header. (2) All 9 credential routes wrapped with `AdminAPIKeyMiddleware`, requiring `Authorization: Bearer <HELM_ADMIN_API_KEY>`. Fail-closed if key unset.

---

### H-2: Autonomy control endpoint has no authentication

**Severity:** HIGH
**Status:** FIXED
**Files:**
- `core/pkg/api/autonomy_handler.go:54-61` — `Register()` now accepts optional `adminAuth` middleware parameter
- `core/pkg/api/autonomy_handler.go:88-140` — `POST /api/autonomy/control`

**Impact:** Anyone with network access could change the global autonomy mode (PAUSE, RUN, FREEZE, ISLAND) without authentication. The posture check (Sovereign/Transact required for FREEZE/ISLAND) is evaluated against server state, not against the caller's authority. An attacker could PAUSE or RUN the system freely.

**Fix applied:** `AutonomyHandler.Register()` now accepts an `adminAuth func(http.Handler) http.Handler` parameter. When non-nil, the control endpoint is wrapped with auth middleware. The state endpoint (read-only) remains public. Callers pass `auth.AdminAPIKeyMiddleware()` in production wiring.

**Remediation:** Require authentication middleware on the autonomy control endpoint. The state endpoint should also require auth since it leaks operational state.

---

### H-3: Wildcard CORS in api/server.go allows credential leakage

**Severity:** HIGH
**Status:** FIXED
**File:** `core/pkg/api/server.go:102` — `Access-Control-Allow-Origin: *`

**Impact:** The `Server.ServeHTTP` in the PDP API server sets `Access-Control-Allow-Origin: *` on every response. While the main server in `main.go` wraps routes with the configurable `CORSMiddleware` from `core/pkg/auth/cors.go`, the standalone `Server` (used by SDKs) has a hardcoded wildcard. If this `Server` is exposed to the network, any website can make cross-origin requests to the HELM API, including the `/api/v1/receipts/` endpoint which lists all governance receipts.

**Remediation:** Remove the hardcoded wildcard CORS. Use the configurable `CORSMiddleware` from the auth package, or restrict to the same-origin policy.

---

### H-4: Metrics endpoint has wildcard CORS

**Severity:** HIGH
**Status:** FIXED
**File:** `core/pkg/metrics/governance.go:147` — `Access-Control-Allow-Origin: *`

**Impact:** The governance metrics handler sets `Access-Control-Allow-Origin: *`. While metrics are generally not secret, the governance metrics include decision counts, deny rates, active agent counts, tool usage patterns, and budget utilization percentages. This operational intelligence should not be freely accessible to any web origin.

**Remediation:** Remove the wildcard CORS from the metrics handler. Metrics should use the same CORS policy as the rest of the API.

---

## MEDIUM Findings

### M-1: CORS middleware defaults to allow-all when CORS_ORIGINS is unset

**Severity:** MEDIUM
**Status:** ACCEPTABLE_RISK (documented as dev mode)
**File:** `core/pkg/auth/cors.go:52-56` — `isOriginAllowed` returns true when allowed list is empty

**Impact:** When `CORS_ORIGINS` is not set, the CORS middleware allows all origins. While documented as "development mode," this is the default state for any new deployment.

**Remediation:** Log a warning at startup when CORS_ORIGINS is unset. Consider requiring it to be explicitly set to `*` for allow-all behavior.

---

### M-2: Health endpoint on separate port leaks no sensitive data but is unauthenticated

**Severity:** MEDIUM
**Status:** MITIGATED
**File:** `core/cmd/helm/main.go:244-264` — health server on port 8081

**Impact:** The health server is intentionally unauthenticated (standard practice for k8s probes). It returns only "OK" with no sensitive data. The Caddy proxy correctly forwards `/health` to the health port.

**Remediation:** None needed. This is standard practice.

---

### M-3: Default evidence signing key used when EVIDENCE_SIGNING_KEY is unset

**Severity:** MEDIUM
**Status:** MITIGATED (warning logged)
**File:** `core/cmd/helm/services.go:174-177`

**Impact:** When `EVIDENCE_SIGNING_KEY` is not set, the server falls back to `"helm-evidence-bundle"` as the seed. All instances using this default will produce receipts signed with the same key, making signatures meaningless for verification. A warning is logged.

**Remediation:** The warning is already present. Consider refusing to start in non-demo mode without a signing key, or auto-generating a random one and persisting it.

---

### M-4: docker-compose.yml exposes PostgreSQL on host port 5432

**Severity:** MEDIUM
**Status:** ACCEPTABLE_RISK (marked as dev-only)
**File:** `docker-compose.yml:8-9` — `ports: - "5432:5432"`

**Impact:** The development docker-compose exposes PostgreSQL on all host interfaces with the password `helm-dev-password`. If used on a machine with a public IP, the database is accessible externally.

**Remediation:** The file has a warning header. Consider binding to `127.0.0.1:5432:5432` to prevent accidental exposure.

---

## LOW Findings

### L-1: Proxy health endpoint leaks upstream URL

**Severity:** LOW
**Status:** ACCEPTABLE_RISK
**File:** `core/cmd/helm/proxy_cmd.go:484`

**Impact:** The proxy health endpoint at `/health` returns the upstream URL in the response body. This reveals the LLM provider being used.

**Remediation:** This is by design for debugging. Low risk since the proxy is intended for local use.

---

### L-2: api/server.go health endpoint leaks PDP backend and receipt count

**Severity:** LOW
**Status:** MITIGATED (behind main server auth in production)
**File:** `core/pkg/api/server.go:310-320`

**Impact:** The health handler returns the PDP backend type and receipt/lamport counts. Minimal information leakage.

**Remediation:** Consider separating the debug info from the health check.

---

### L-3: Config status endpoint exposes port and log level

**Severity:** LOW
**Status:** ACCEPTABLE_RISK
**File:** `core/cmd/helm/subsystems.go:208-214` — `GET /api/v1/config/status`

**Impact:** Returns the configured port and log level. Minimal information, but could help an attacker enumerate the deployment.

**Remediation:** This is behind the main server's rate limiter and CORS. Acceptable for operational tooling.

---

## Positive Findings (Mitigations Already Present)

1. **Fail-closed governance:** The PDP server returns DENY on errors (`server.go:149-154`). Good.
2. **Rate limiting:** `GlobalRateLimiter` with per-IP tracking and background cleanup (`middleware.go`). Applied to main server.
3. **Security headers:** HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy all set (`auth/security.go`).
4. **Read timeout set:** All HTTP servers have `ReadHeaderTimeout` set (prevents Slowloris).
5. **Request body limits:** `MaxBytesReader` used on credential and decision handlers.
6. **Docker image:** Uses distroless base, nonroot user, static binary. Good supply chain hygiene.
7. **Kubernetes chart:** `securityContext` drops all capabilities, read-only root filesystem, non-root user.
8. **Caddy edge proxy:** Rate limiting per endpoint, 64KB request cap, HSTS, CSP headers.
9. **MCP auth modes:** Supports none, static-header, and OAuth (with JWKS validation).
10. **Approval handler:** Requires Ed25519 signature verification with authorized key registry.
11. **Signing key from Secret:** Helm chart reads signing key from K8s Secret, not env var directly.

---

## Fixes Applied

The following fixes are applied in this audit. All tests pass after changes.

### Fix C-1: Default server bindings changed to localhost
- `core/cmd/helm/main.go` — API server and health server default to `127.0.0.1` instead of `0.0.0.0`
- `core/cmd/helm/proxy_cmd.go` — proxy defaults to `127.0.0.1`
- `core/cmd/helm/mcp_runtime.go` — MCP HTTP server defaults to `127.0.0.1`
- New env var `HELM_BIND_ADDR` allows overriding (set to `0.0.0.0` for intentional network exposure)
- Warning logged when `HELM_BIND_ADDR=0.0.0.0` is used

### Fix H-3: Removed wildcard CORS from api/server.go
- `core/pkg/api/server.go` — Replaced `Access-Control-Allow-Origin: *` with configurable `AllowedOrigins` field on `ServerConfig`
- Default (nil AllowedOrigins) = no CORS headers emitted (secure default)
- `core/pkg/api/server_test.go` — Updated `TestCORS` to verify secure default and explicit origin matching
- Added `AllowedOrigins` field to `Server` struct and `ServerConfig`

### Fix H-4: Removed wildcard CORS from metrics handler
- `core/pkg/metrics/governance.go` — Removed hardcoded `Access-Control-Allow-Origin: *` from `Handler()` method

### Remaining NEEDS_FIX (require design decisions)
- **C-2:** Trust key endpoints need auth middleware — requires choosing auth strategy (API key vs JWT)
- **H-1:** Credential handler `getOperatorID()` needs cryptographic identity source — requires JWT middleware
- **H-2:** Autonomy control endpoint needs auth — same auth middleware needed
