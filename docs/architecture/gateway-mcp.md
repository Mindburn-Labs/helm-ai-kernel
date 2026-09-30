# Gateway MCP endpoint (HELM-751 K3)

`helm-gateway` serves its effect types to episode workers as MCP tools, so a
worker has one network exit for both halves of its work: its model calls
(`/v1/*`, see the model gateway) and its effects (`/mcp`). The endpoint is the
package `core/pkg/gateway/mcpserver`. It holds no credential and no authority
store of its own. A tool call is an effect proposal, admitted, dispatched and
observed by the same admission service as every other effect, under the
identity of the worker's token.

## Where it is served

- **Listener.** The worker listener (`--worker-listen`), at `/mcp`, beside
  `/v1/*`. The main listener serves no MCP, and the worker listener serves no
  effect API. There is one worker listener and one worker token profile: the
  endpoint mounts on them and adds neither.
- **Token.** The worker listener's own: audience `HELM_GATEWAY_WORKER_AUDIENCE`,
  no client certificate, a `helm_episode` claim, and one scope. Tools are
  called with `helm.gateway.propose`. A token with `helm.gateway.read` lists
  tools and reads its episode's attempts, and is denied every effect. A token
  never carries `helm.gateway.execute`: the effect API's `Dispatch` and
  `Observe` still ask for it.
- **Who.** Agent principals only. A human or service principal with an episode
  token is refused with 403 whatever mandates it holds. The kind is the
  gateway's own row for the principal, not a claim.
- **Configuration.** None of its own. The worker listener needs the model
  routes file like the model endpoints do (`HELM_GATEWAY_MODEL_ROUTES_FILE`),
  and `serve` refuses to start when an effect type that would be a tool cannot
  be given a tool name.

## Identity comes from the token alone

| Fact | Source |
|---|---|
| Principal (the seat) | `sub`, which must be an `agent` principal of the tenant |
| Actor (the workload that carries the call) | `act.sub` |
| Tenant, workspace | `tenant_id`, `workspace_id` |
| Episode, work item, organization version | `helm_episode` (`episode_id`, `work_item_id`, `organization_version_id`) |

Nothing in a request names any of them. A `params` object, a tool's arguments
or an effect's arguments with a field for a case, a commitment or an episode is
a malformed call, and `_meta` is the client's own and read for nothing. The
work reference of every attempt is the claim's work item (`case_id`).

## Two eras on one endpoint

The endpoint is stateless and serves both eras of MCP at once, as a dual-era
server may (MCP versioning, "Backward Compatibility with Initialization-Based
Versions"). No session id is minted, `Mcp-Session-Id` is ignored, there is no
GET stream (405) and nothing is resumable.

| | 2026-07-28 | 2025-03-26, 2025-06-18, 2025-11-25 |
|---|---|---|
| Opens with | any request | `initialize` (and `notifications/initialized`, answered 202) |
| Version | `MCP-Protocol-Version` header and `_meta["io.modelcontextprotocol/protocolVersion"]`, which must agree | negotiated by `initialize`; the header on later requests; none means 2025-03-26 |
| Required | `_meta` protocol version and client capabilities; `Mcp-Method`, and `Mcp-Name` on `tools/call`, which must match the body (Base64 sentinel decoded) | nothing |
| Methods | `server/discover`, `tools/list`, `tools/call` | `ping`, `tools/list`, `tools/call` |
| Results | carry `resultType: "complete"` and the server in `_meta`; `tools/list` and discovery carry `ttlMs` and `cacheScope` | plain |
| Failures | a request that breaks its era's rules is `400` with `-32602` (no or incomplete `_meta`), `-32020` (header and body disagree) or `-32022` (a version not spoken, with `data.supported` and `data.requested`); an unknown method is `404` with `-32601` | `-32601` inside a `200` |

A request that says in its body that it is stateless and does not say so in its
header is a header mismatch, not a legacy request. `initialize` is always the
older eras' and, carrying the stateless version header, is `404`.

Every answer is one JSON object; the server never opens an event stream, and
the request's JSON is refused when it is larger than 256 KiB, is a batch or a
response, repeats a key, or nests more than 64 levels. The request id is a
string of at most 128 bytes or an integer, never null.

## Tools

`tools/list` returns, in name order:

- each **effect type** that some active mandate of the caller names (every link
  of the chain active and inside its validity window now), that a mandate may
  grant, that carries an argument schema and that this gateway performs: the
  declarations of its adapters. `model.inference` is never a tool;
- **`helm_attempt_get`**, always.

A list reflects authority and grants none: a call is admitted afresh from the
locked rows, so a stale list makes a tool visible that is then denied, never
the reverse. `cacheScope` is `private`: the list depends on the credential.

**Names.** The effect type with its dots as underscores: `github.repository.get`
is `github_repository_get`, `github.pull_request.create_draft` is
`github_pull_request_create_draft`. The gateway refuses to start when a name is
not `[A-Za-z0-9_-]{1,64}`, or two effect types collapse to one name.

**Input.** `{"target": string, "arguments": object}`, both required and
nothing else. The target is what the effect acts on, in the form the
declaration gives (`github.com/{owner}/{repo}`), and is never read from the
arguments. The arguments are the effect's own closed schema, embedded without
`$schema`, `$id` and `x-helm`. The gateway validates the exact bytes against
the full schema itself before anything is admitted. `helm_attempt_get` takes
`{"attempt_id": string}`.

## A call

`tools/call` for an effect tool runs in one request, under a context that ends
only at `CallTimeout` (five minutes, never cut short by the client hanging up),
so a permit that was issued is never left unclaimed:

1. **Propose** under the caller's mandates, with a quote of zero in every unit
   its chains sum, the work reference from the claim and the key below.
2. **Admitted:** claim the permit, dispatch through the adapter and read back,
   in the same call. The permit is claimed by the worker's own principal, which
   is what the attempt was proposed through, and the claim records it with the
   workload that carried the token.
3. **Escalated:** stop. Nothing is held or sent.
4. **Denied:** stop, with the reason.

The result is `structuredContent` with the same JSON as text for older
clients. `status` says what happened, and `isError` whether the call did not:

| `status` | `isError` | Meaning |
|---|---|---|
| `succeeded` | false | observed or reconciled as succeeded; `result` and `result_kind` hold the typed result the effect defines |
| `escalated` | false | a human must approve; `attempt_id`. The attempt stays `ESCALATED` until a human decides, and the worker stops and reports it |
| `reconciling` | false | dispatched and not yet known (`UNKNOWN`, in flight): read it again with `helm_attempt_get`, or repeat the call |
| `failed` | true | observed as failed, `reason_code` says why |
| `denied` | true | `reason_code` and `message` say which part of authority refused |
| `rejected`, `expired`, `cancelled` | true | an approver rejected it, nobody decided in time, a stop or an expired permit cancelled it |
| `invalid` | true | the arguments break the tool's schema or the contract above; no attempt was made |
| `conflict`, `refused`, `not_found` | true | the key was used by a different request; a precondition does not hold; there is no such attempt of this episode |

A protocol failure is not a result: an unknown tool is `-32602`, and a ledger
that cannot answer is `-32603` in a `200`, with the instruction to repeat the
call, which the key makes safe.

### Replay

The key is `mcp:<episode_id>:<s|n>:<request id>`, `s` for a string id and `n`
for an integer. Repeating a request with the same id finds the same attempt
and carries it on from wherever it is: one admitted and never sent is sent now
(including one a human approved since), one in flight is read back, and
nothing is ever sent twice. The same id with a different request is a
`conflict`, never the first request's attempt, and another episode, tenant or
id is another call. A client that re-issues a request with a new id (as the
stateless revision asks of a broken stream) makes a new attempt; the id is the
call's identity.

## Episode attempts (N1) and read isolation

An attempt proposed with an episode token records the episode, the work item
(as its `case_id`) and the organization version, from the verified claim alone
(schema migration 8; `EffectAttempt.episode`). A token with an episode claim
reads only the attempts of its own episode that its own principal proposed, in
`GetAttempt`, `GetAttemptContent`, `ListAttempts`, `helm_attempt_get` and the
stored response of a model call: any other attempt of the same tenant, another
episode's, another seat's under the same episode id and the Control Plane's,
is `not_found`, the same answer as an attempt that does not exist. The Control
Plane's service principal with `helm.gateway.read` reads every attempt of its
token's tenant and workspace, and lists by `episode_id`.

## What is not served

Server-to-client requests, sampling, elicitation and roots; `subscriptions/listen`
and list-change notifications (`listChanged` is false); the tasks extension;
multi round-trip results; pagination (a cursor is refused); resumable streams;
and `ping` in the stateless revision, which removed it.

The work tools of the Control Plane's composition (`helm.work.*`) are offered
the same way once their adapter declares them. The typed result an observation
can carry is the set the kernel defines (the GitHub results); an effect type
that returns more needs its member in `Observation` first.

## Evidence

- Protocol: `core/pkg/gateway/mcpserver` `TestLegacyHandshakeNegotiatesAndKeepsNothing`,
  `TestModernDiscoveryAndDeterministicPrivateList`, `TestModernRequestValidation`,
  `TestTransportChecksOriginMethodAuthenticationAndBounds`.
- Calls, on PostgreSQL 16 through HTTP and the real token check:
  `TestPostgresToolsListReflectsTheCallersMandates`,
  `TestPostgresAnAllowedCallIsDispatchedAndObservedInTheSameCall`,
  `TestPostgresAnEscalatedCallIsAStructuredResultAndContinuesAfterApproval`,
  `TestPostgresADeniedCallIsAToolErrorWithItsReasonCode`,
  `TestPostgresAnUnknownOutcomeIsReconcilingUntilItIsKnown`,
  `TestPostgresAReplayedCallIsTheSameAttempt`,
  `TestPostgresTheEpisodeComesFromTheClaimNotTheBody`.
- Isolation: `TestPostgresATokenOfAnotherTenantReachesNothingOfThisOne`,
  `TestPostgresAnotherEpisodesAttemptIsNotFound` and, in `admission`,
  `TestPostgresAnEpisodeReadsOnlyItsOwnAttempts`.
- The mount: `core/pkg/gateway/runtime` `TestServeMountsTheMCPEndpointOnTheWorkerListenerOnly`.
