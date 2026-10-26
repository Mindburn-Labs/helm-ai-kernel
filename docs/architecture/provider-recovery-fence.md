# Scoped provider recovery fence

HELM-1039 implements an initial gateway capability: a durable hold on native
attempts for one provisioned organization version in one token workspace.
Provider-enabled backup, restore, resume and signed recovery receipts remain
unsupported.

## Authority and scope

`FenceRecovery` requires existing `helm.gateway.stop` authority from a currently
active human. Its single-use token carries one `helm_recovery_fence` detail
binding operation, installation correlation, organization, provisioned version
and expected prior generation. Tenant and workspace come from the token.
Installation correlation is not an installer credential. Episode, continuation
and reassignment credentials cannot control or read recovery operations.

The gateway verifies `authority_provisions`, retains its plan digest/revision
and refuses versions shared by multiple organizations. Coverage is native
attempts carrying a verified episode version. Legacy unversioned attempts lack
a source-owned organization binding and remain outside this capability. It
does not cover an adapter's independent dispatch store.

`GetRecoveryFence` and `ListRecoveryAttempts` require `helm.gateway.read` from
an active human in the exact operation scope and do not contact providers.
`Observe` retains the original attempt's workload/episode checks. Existing
`Cancel` authorization and reservation disposition remain unchanged. Recovery
never uses Stop's cancellation, permit-voiding or exposure-release transitions.

## Durable cutoff

Migration 13 adds gateway-owned fences, current scopes, original membership
and checkpoint correlations under forced tenant row security. Generation
advances by compare-and-set on the exact workspace/organization/version scope.
Only an exact replay of the current operation is idempotent; stale callers
cannot replace or acknowledge newer generations.

Fence creation takes the existing tenant control row `FOR UPDATE`. Admission
and claims hold it `FOR SHARE` through commit. The fence then captures original
membership and its immutable cutoff digest. It does not bump the tenant version
or invalidate unrelated permits. Other workspace and organization versions
remain live. A pre-cutoff claim may begin provider I/O after acknowledgement;
its original attempt remains inventoried.

Triggers fence older attempt writers and model claims, rolling back late permit
consumption. Read-only idempotency lookup can still find original attempts.
Provisioning cannot replace the held version or assign it to a neighbor org.

Membership intentionally has no attempt foreign key. Its `KEY SHARE` check
would wait on a claim's locked attempt while that claim waits for the tenant
row, creating a lock cycle. Membership is inserted only from native attempts
under the exclusive control lock. Runtime grants permit neither attempt nor
membership deletion, and membership is append-only. No permit, reservation,
observation or provider result is copied.

The gateway database is outside CP snapshot restore. Rolling it back with CP,
deleting its fence or restoring all authoritative stores from an old snapshot
is unsupported. A CP projection cannot lower its generation or revive a permit.

## Checkpoint and governed resume ownership

`BindRecoveryCheckpoint` requires the current exact operation/generation,
single-use stop authority bound to CP digest/native inventory watermark, and
no in-flight, unknown or unresolved model settlement. Changed inventory,
checkpoint bytes, scope and generations are refused. This immutable correlation
proves neither CP snapshot consistency nor restore eligibility.

The next resume producer must use existing effect admission, a current mandate,
distinct step-up approval, dispatch claim, observation and signed evidence.
It must bind current operation/generation, CP snapshot, installed source/image/
schema/trust identity, native checkpoint and reconciled original effects.
Release belongs in a native transaction with the existing receipt and
ProofGraph/EvidencePack boundary. Current authority and financial eligibility
must be revalidated without recreating or mutating the financial ledger.
There is no administrative release method or installer exception.

A consistent CP snapshot producer, adapter-store participation and the governed
signed resume producer remain prerequisites for provider restore support.
Unknown effects use their original observation path. New attempts or new
idempotency keys cannot probe whether an old provider operation succeeded.

## Verification

Restricted-role PostgreSQL tests exercise native provision/step-up approval,
original attempts, concurrent claims, late sends, unknown outcomes, checkpoints,
stale generations, cross-scope reads and neighbor liveness. The process test
kills dispatch after a controlled provider accepts the original request, then
recreates the service and observes that same operation with one write. Only
external transport is controlled. These source/storage proofs remain separate
from real-provider restore, publication and deployed runtime qualification.
