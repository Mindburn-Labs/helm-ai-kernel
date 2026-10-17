# Gateway activity trail

`activitytrail` is a Kernel-owned, observed-only source for GitHub default-branch
changes. It does not create an effect attempt, approval, permit, or receipt.
An enabled source is classified `observed-only`; a disabled or absent source is
`unmanaged`. This classification describes the source, not mediation of a
particular GitHub change.

The source stores an authenticated repository identity, default branch, and
head cursor. `PollDefaultBranch` reads the current GitHub ref and pages through
the complete compare result before advancing the cursor. An incomplete or
inconsistent comparison leaves the cursor in place and records an error.
Each resulting repository/ref/before/after fact has a stable SHA-256 digest.
Source evidence is separate from the fact, so repeated provider deliveries and
compare reads do not duplicate an observation. A compare can span multiple
pushes between polls; that span is an observed ref change, not proof of one
individual push.

An existing internal ingress may call `IngestSignedPush` with the original body,
delivery ID, and GitHub `X-Hub-Signature-256` value. It verifies the HMAC before
storing the provider-supplied sender. The push payload has no action timestamp;
`provider_time` stays unset. `PollRepositoryEvents` can add a matching event's
actor and `created_at` later. Compare-only facts leave actor and provider time
unset. Conflicting provider attribution fails rather than replacing a stored
fact. The Events API is delayed and windowed, so neither a poll nor a signed
push alone guarantees full actor and provider-time attribution within 60
seconds. `attribution_complete` means the current stored observations have
those fields after both poll types have run without a known gap; it does not
prove complete repository history. `event_window_capped` reports a full
300-event read window and stays set until a new baseline is enabled, because
later short windows cannot establish that the earlier gap was recovered.

`gateway_activity_sources`, `gateway_activity_observations`, and
`gateway_activity_evidence` use forced tenant row-level security. The package's
`Migrate` runs after `admission.Migrate` and maintains its own versioned
`gateway_activity_schema_migrations` journal. The gateway runtime role needs
`SELECT`, `INSERT`, and `UPDATE` on the three data tables, with no journal or
`DELETE` grant. Application calls set `app.current_tenant` inside a transaction.
The package does not apply migrations while serving requests.

`ActivityTrailService` defines authenticated read-only Connect RPCs:
`GetCoverage`, `ListObservations`, and `ListOwnerExceptions`. The read token
supplies tenant and workspace; the request supplies only the canonical
`github.com/{owner}/{repo}` identity. Lists use newest-first keyset pagination,
default page size 50, maximum 100, and an opaque scope-bound cursor. The owner
exception projection represents each stored observed-only fact as `change made
outside HELM`; it does not assert that another system lacked a governed
attempt. The gateway migration, runtime poller, optional signed internal
ingress, and authenticated read handler are mounted in the gateway process.
There is no public activity write RPC.

## Runtime wiring

The migration command calls `activitytrail.Migrate(ctx, db)` after
`admission.Migrate(ctx, db)`. Runtime construction uses
`activitytrail.New(db, githubAPIURL, httpClient)` and registers
`(&server.ActivityServer{Trail: trail, Auth: authenticator}).Handler()` on the
existing authenticated gateway mux. The generated Go client is
`gatewayv1.NewActivityTrailServiceClient(httpClient, gatewayURL)` with methods
`GetCoverage`, `ListObservations`, and `ListOwnerExceptions`. The exact request
types are `GetCoverageRequest`, `ListObservationsRequest`, and
`ListOwnerExceptionsRequest`; responses use the matching `Response` suffix.

The operator supplies `gateway.activity.sourcesFile` as JSON with a `sources`
array. Each entry has `tenant_id`, `workspace_id`, `repository` in
`github.com/{owner}/{repo}` form, and an explicit `enabled` boolean. The
gateway binds each source to the existing GitHub App installation allowlist,
mints a repository-scoped read token, establishes a baseline for new or
re-enabled sources, and polls the default branch and repository events. A
disabled entry preserves prior observations; removing an entry leaves its
stored classification unchanged. The poll interval defaults to one minute and
can be set with `gateway.activity.pollInterval` from 15 seconds to one hour.

If `gateway.activity.webhookSecretKey` names a key in the gateway GitHub App
secret, the main gateway listener accepts `POST /internal/github/activity`.
The handler verifies the GitHub HMAC against the original body before reading
provider identity. It maps the signed repository to the operator-configured
tenant/workspace scopes and calls `IngestSignedPush`; tenant and workspace never
come from the GitHub body. The deployment network policy controls which peers
can reach the listener. A missing webhook secret leaves the ingress unmounted;
polling and read RPCs still operate.
