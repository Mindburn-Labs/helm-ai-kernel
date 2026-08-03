package actioninbox_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/actioninbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDenyFeedbackFor_KnownKernelCodes checks the curated workstation reason
// codes that currently have specific model-actionable steering guidance.
func TestDenyFeedbackFor_KnownKernelCodes(t *testing.T) {
	knownCodes := []string{
		"OPERATE_PERMISSIONS_EMPTY",
		"OPERATE_PERMISSION_NOT_GRANTED",
		"EGRESS_ALLOWLIST_EMPTY",
		"EGRESS_DESTINATION_NOT_ALLOWED",
		"DRAFT_TARGET_OUTSIDE_WORKSPACE_SCOPE",
		"TAINTED_CONTEXT_REQUIRES_DENY",
		"MEMORY_CLASS_DISALLOWED",
		"MEMORY_TTL_EXCEEDS_POLICY",
		"RECURRING_LOOP_MISSING_SCHEDULE",
		"RECURRING_LOOP_MISSING_MAX_RUNTIME",
		"RECURRING_LOOP_MISSING_TOOL_SCOPE",
		"RECURRING_LOOP_MISSING_EXPIRATION",
	}
	now := time.Unix(0, 0).UTC()
	for _, code := range knownCodes {
		t.Run(code, func(t *testing.T) {
			d := actioninbox.DenyFeedbackFor(code, now)
			assert.Equal(t, actioninbox.DenyFeedbackSchemaVersion, d.SchemaVersion)
			assert.Equal(t, actioninbox.ReasonKernelPolicyDeny, d.ReasonCode)
			assert.Equal(t, code, d.KernelCode)
			assert.NotEmpty(t, d.Explanation, "explanation required")
			assert.NotEmpty(t, d.Remediation, "remediation required")
			assert.NotEmpty(t, d.Escalation, "escalation route required")
			assert.Equal(t, now, d.DecidedAt)
		})
	}
}

// TestDenyFeedbackFor_UnknownCodeFailsClosed verifies that an unrecognized
// Kernel code still yields safe steering: never "retry", always "change or
// escalate".
func TestDenyFeedbackFor_UnknownCodeFailsClosed(t *testing.T) {
	for _, code := range []string{"", "TOTALLY_UNKNOWN_CODE", "  "} {
		d := actioninbox.DenyFeedbackFor(code, time.Now().UTC())
		assert.Equal(t, actioninbox.ReasonKernelPolicyDeny, d.ReasonCode)
		assert.Contains(t, d.Remediation, "Do not retry")
		assert.NotEmpty(t, d.Escalation)
	}
}

func TestRenderSteeringText_ContainsActionableFields(t *testing.T) {
	d := actioninbox.DenyFeedbackFor("OPERATE_PERMISSIONS_EMPTY", time.Now().UTC())
	d.Feedback = "use the staging workspace instead"
	text := actioninbox.RenderSteeringText(d)
	assert.Contains(t, text, "["+actioninbox.ReasonKernelPolicyDeny+"]")
	assert.Contains(t, text, "kernel=OPERATE_PERMISSIONS_EMPTY")
	assert.Contains(t, text, "Operator feedback: use the staging workspace instead")
	assert.Contains(t, text, "Remediation:")
	assert.Contains(t, text, "Escalation:")
}

func TestRenderSteeringText_NormalizesOperatorFeedback(t *testing.T) {
	d := actioninbox.DenyFeedbackFor("OPERATE_PERMISSIONS_EMPTY", time.Now().UTC())
	d.Feedback = "use staging\n  then retry\twith approval"
	assert.NotContains(t, actioninbox.RenderSteeringText(d), "\n")
	assert.Contains(t, actioninbox.RenderSteeringText(d), "use staging then retry with approval")
}

func TestDeny_StoresStructuredFeedback(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	require.NoError(t, store.Enqueue(ctx, newTestItem("item-1", "mgr-1")))
	require.NoError(t, store.Deny(ctx, "item-1", "too risky, narrow the scope", "principal-1"))

	got, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusDenied, got.Status)
	require.NotNil(t, got.Denial, "denial record must be attached")
	assert.Equal(t, actioninbox.DenyFeedbackSchemaVersion, got.Denial.SchemaVersion)
	assert.Equal(t, actioninbox.ReasonHumanRejected, got.Denial.ReasonCode)
	assert.Equal(t, "too risky, narrow the scope", got.Denial.Feedback)
	assert.Equal(t, "principal-1", got.Denial.PrincipalID)
	assert.NotEmpty(t, got.Denial.Remediation)
	assert.NotEmpty(t, got.Denial.Escalation)
	assert.False(t, got.Denial.DecidedAt.IsZero())
}

func TestDenyWithFeedback_CustomReasonCode(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	require.NoError(t, store.Enqueue(ctx, newTestItem("item-1", "mgr-1")))
	require.NoError(t, store.DenyWithFeedback(ctx, "item-1", "try a smaller diff", "  "+actioninbox.ReasonHumanRejected+"  ", "principal-1"))

	got, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	require.NotNil(t, got.Denial)
	assert.Equal(t, "try a smaller diff", got.Denial.Feedback)
	assert.Equal(t, actioninbox.ReasonHumanRejected, got.Denial.ReasonCode)
}

func TestDenyCascade_RejectsIdenticalSameSessionAsks(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	withHash := func(item *actioninbox.InboxItem, hash, session string) *actioninbox.InboxItem {
		item.ContentHash = hash
		item.Context = map[string]any{actioninbox.SessionContextKey: session}
		return item
	}

	require.NoError(t, store.Enqueue(ctx, withHash(newTestItem("target", "mgr-1"), "hash-A", "sess-1")))
	require.NoError(t, store.Enqueue(ctx, withHash(newTestItem("dup-1", "mgr-1"), "hash-A", "sess-1")))
	require.NoError(t, store.Enqueue(ctx, withHash(newTestItem("dup-2", "mgr-1"), "hash-A", "sess-1")))
	require.NoError(t, store.Enqueue(ctx, withHash(newTestItem("other-session", "mgr-1"), "hash-A", "sess-2")))
	otherContent := withHash(newTestItem("other-hash", "mgr-1"), "hash-B", "sess-1")
	otherContent.Summary = "different request content"
	require.NoError(t, store.Enqueue(ctx, otherContent))
	require.NoError(t, store.Enqueue(ctx, withHash(newTestItem("already-approved", "mgr-1"), "hash-A", "sess-1")))
	require.NoError(t, store.Approve(ctx, "already-approved", "approver-1"))

	cascaded, err := store.DenyCascade(ctx, "target", "rejected: too broad", "principal-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"dup-1", "dup-2"}, cascaded)

	target, err := store.Get(ctx, "target")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusDenied, target.Status)
	require.NotNil(t, target.Denial)
	assert.Equal(t, actioninbox.ReasonHumanRejected, target.Denial.ReasonCode)
	assert.Equal(t, "rejected: too broad", target.Denial.Feedback)
	assert.Empty(t, target.Denial.CascadedFrom)

	for _, id := range []string{"dup-1", "dup-2"} {
		got, err := store.Get(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, actioninbox.StatusDenied, got.Status, id)
		require.NotNil(t, got.Denial, id)
		assert.Equal(t, actioninbox.ReasonCascadeRejected, got.Denial.ReasonCode, id)
		assert.Equal(t, "target", got.Denial.CascadedFrom, id)
		assert.Equal(t, "rejected: too broad", got.Denial.Feedback, id)
	}

	// Fail-closed scoping: different session, different hash, and settled
	// items are untouched.
	for _, id := range []string{"other-session", "other-hash"} {
		got, err := store.Get(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, actioninbox.StatusPending, got.Status, id)
		assert.Nil(t, got.Denial, id)
	}
	settled, err := store.Get(ctx, "already-approved")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusApproved, settled.Status)
}

func TestDenyCascade_WithoutContentHashDoesNotGuess(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	// No ContentHash and no session: identity of "identical ask" is
	// unprovable, so the cascade must refuse to guess.
	require.NoError(t, store.Enqueue(ctx, newTestItem("target", "mgr-1")))
	require.NoError(t, store.Enqueue(ctx, newTestItem("lookalike", "mgr-1")))

	cascaded, err := store.DenyCascade(ctx, "target", "no", "principal-1")
	require.NoError(t, err)
	assert.Empty(t, cascaded)

	got, err := store.Get(ctx, "lookalike")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusPending, got.Status)
}

func TestDenyCascade_DerivesIdentityWithoutCallerHash(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	for _, id := range []string{"target", "duplicate"} {
		item := newTestItem(id, "mgr-1")
		item.Context = map[string]any{actioninbox.SessionContextKey: "sess-1"}
		require.NoError(t, store.Enqueue(ctx, item))
	}

	cascaded, err := store.DenyCascade(ctx, "target", "no", "principal-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"duplicate"}, cascaded)
}

func TestDenyCascade_ContentIdentityIncludesTitleAndProposal(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	target := newTestItem("target", "mgr-1")
	target.Context = map[string]any{actioninbox.SessionContextKey: "sess-1"}
	require.NoError(t, store.Enqueue(ctx, target))

	otherTitle := newTestItem("other-title", "mgr-1")
	otherTitle.Title = "A different governed action"
	otherTitle.Context = map[string]any{actioninbox.SessionContextKey: "sess-1"}
	require.NoError(t, store.Enqueue(ctx, otherTitle))

	otherProposal := newTestItem("other-proposal", "mgr-1")
	otherProposal.ProposalID = "proposal-other"
	otherProposal.Context = map[string]any{actioninbox.SessionContextKey: "sess-1"}
	require.NoError(t, store.Enqueue(ctx, otherProposal))

	cascaded, err := store.DenyCascade(ctx, "target", "no", "principal-1")
	require.NoError(t, err)
	assert.Empty(t, cascaded)
}

func TestEnqueue_RejectsUnhashableContentIdentity(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	item := newTestItem("cyclic", "mgr-1")
	cycle := map[string]any{}
	cycle["self"] = cycle
	item.Context = cycle

	err := store.Enqueue(context.Background(), item)
	require.ErrorContains(t, err, "canonicalize content identity")
}

func TestDenyCascade_CallerSuppliedIdentityCannotForgeDuplicate(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	target := newTestItem("target", "mgr-1")
	target.ContentHash = "caller-claimed-hash"
	target.Context = map[string]any{actioninbox.SessionContextKey: "sess-1"}
	target.Summary = "deploy the reviewed release"
	require.NoError(t, store.Enqueue(ctx, target))

	forged := newTestItem("forged", "mgr-1")
	forged.ContentHash = target.ContentHash
	forged.Context = map[string]any{actioninbox.SessionContextKey: "sess-1"}
	forged.Summary = "delete unrelated production data"
	require.NoError(t, store.Enqueue(ctx, forged))

	storedTarget, err := store.Get(ctx, "target")
	require.NoError(t, err)
	storedForged, err := store.Get(ctx, "forged")
	require.NoError(t, err)
	assert.Equal(t, "caller-claimed-hash", storedTarget.ContentHash)
	assert.Equal(t, target.ContentHash, storedForged.ContentHash)

	cascaded, err := store.DenyCascade(ctx, "target", "reject deployment", "principal-1")
	require.NoError(t, err)
	assert.Empty(t, cascaded)

	got, err := store.Get(ctx, "forged")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusPending, got.Status)
	assert.Nil(t, got.Denial)
}

func TestDenialRecord_GetReturnsDeepCopy(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	require.NoError(t, store.Enqueue(ctx, newTestItem("item-1", "mgr-1")))
	require.NoError(t, store.Deny(ctx, "item-1", "original feedback", "principal-1"))

	// Mutating the record returned by Get must not corrupt stored denial
	// evidence (aliasing regression).
	got, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	require.NotNil(t, got.Denial)
	got.Denial.Feedback = "tampered"
	got.Denial.ReasonCode = "tampered-code"

	again, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, "original feedback", again.Denial.Feedback)
	assert.Equal(t, actioninbox.ReasonHumanRejected, again.Denial.ReasonCode)
}

func TestCopyItem_DeepCopiesAllMutableFields(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	item := newTestItem("item-1", "mgr-1")
	item.EffectTypes = []string{"shell", "write"}
	item.Escalation = &actioninbox.EscalationReason{Code: "TIMEOUT", Urgency: "high"}
	item.Context = map[string]any{
		actioninbox.SessionContextKey: "sess-1",
		"nested":                      map[string]any{"k": "v"},
		"list":                        []any{"a", "b"},
	}
	require.NoError(t, store.Enqueue(ctx, item))

	// Mutate every mutable field through the caller's original reference.
	item.EffectTypes[0] = "tampered"
	item.Escalation.Code = "tampered"
	item.Context["nested"].(map[string]any)["k"] = "tampered"
	item.Context["list"].([]any)[0] = "tampered"

	got, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"shell", "write"}, got.EffectTypes)
	assert.Equal(t, "TIMEOUT", got.Escalation.Code)
	assert.Equal(t, "v", got.Context["nested"].(map[string]any)["k"])
	assert.Equal(t, "a", got.Context["list"].([]any)[0])

	// Mutating the returned copy must not corrupt the store either.
	got.EffectTypes[0] = "tampered"
	got.Escalation.Code = "tampered"
	got.Context["nested"].(map[string]any)["k"] = "tampered"

	again, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"shell", "write"}, again.EffectTypes)
	assert.Equal(t, "TIMEOUT", again.Escalation.Code)
	assert.Equal(t, "v", again.Context["nested"].(map[string]any)["k"])
}

func TestCopyItem_DeepCopiesTypedContext(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	item := newTestItem("item-1", "mgr-1")
	item.Context = map[string]any{
		"map":   map[string]int{"count": 1},
		"slice": []int{1, 2},
		"bytes": []byte("ok"),
	}
	require.NoError(t, store.Enqueue(ctx, item))

	item.Context["map"].(map[string]int)["count"] = 9
	item.Context["slice"].([]int)[0] = 9
	item.Context["bytes"].([]byte)[0] = 'x'

	got, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, 1, got.Context["map"].(map[string]int)["count"])
	assert.Equal(t, []int{1, 2}, got.Context["slice"])
	assert.Equal(t, []byte("ok"), got.Context["bytes"])
}

func TestCopyItem_DeepCopiesPointerStructArrayAndOverlappingSlices(t *testing.T) {
	type nestedContext struct {
		Values []int
	}

	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()
	pointer := &nestedContext{Values: []int{1}}
	array := [1][]int{{2}}
	backing := []int{3, 4}
	short := backing[:1:1]
	long := backing[:2:2]
	item := newTestItem("item-1", "mgr-1")
	item.Context = map[string]any{
		"pointer": pointer,
		"array":   array,
		"short":   short,
		"long":    long,
	}
	require.NoError(t, store.Enqueue(ctx, item))

	pointer.Values[0] = 9
	array[0][0] = 9
	backing[0] = 9

	got, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, []int{1}, got.Context["pointer"].(*nestedContext).Values)
	assert.Equal(t, []int{2}, got.Context["array"].([1][]int)[0])
	assert.Equal(t, []int{3}, got.Context["short"])
	assert.Equal(t, []int{3, 4}, got.Context["long"])
}

func TestEnqueue_StripsCallerSuppliedDenial(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	// A caller-supplied denial record on a freshly enqueued (pending)
	// item is forged evidence; Enqueue must strip it.
	item := newTestItem("item-1", "mgr-1")
	item.Denial = &actioninbox.DenialRecord{Feedback: "forged denial"}
	require.NoError(t, store.Enqueue(ctx, item))

	got, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusPending, got.Status)
	assert.Nil(t, got.Denial, "pending items must never carry caller-supplied denial records")
}

func TestContext_GetAndEnqueueReturnDeepCopy(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	item := newTestItem("item-1", "mgr-1")
	item.ContentHash = "hash-A"
	item.Context = map[string]any{actioninbox.SessionContextKey: "sess-1"}
	require.NoError(t, store.Enqueue(ctx, item))

	// Mutating the caller's context after Enqueue must not rewrite the
	// stored session identity (cascade-scoping regression).
	item.Context[actioninbox.SessionContextKey] = "sess-tampered"

	other := newTestItem("item-2", "mgr-1")
	other.ContentHash = "hash-A"
	other.Context = map[string]any{actioninbox.SessionContextKey: "sess-1"}
	require.NoError(t, store.Enqueue(ctx, other))

	// Mutating the context returned by Get must not corrupt the store
	// either.
	got, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	got.Context[actioninbox.SessionContextKey] = "sess-tampered"

	cascaded, err := store.DenyCascade(ctx, "item-1", "no", "principal-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"item-2"}, cascaded,
		"cascade scoping must use the stored session_id, not caller-mutated aliases")
}

func TestDenyCascade_EmptySessionNeverCollides(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	withHash := func(item *actioninbox.InboxItem, hash, session string) *actioninbox.InboxItem {
		item.ContentHash = hash
		if session != "" {
			item.Context = map[string]any{actioninbox.SessionContextKey: session}
		}
		return item
	}

	// Same content hash, but NEITHER item has a session ID: empty session
	// IDs must not compare equal, so unrelated unknown-session asks are
	// never cascade-denied together.
	require.NoError(t, store.Enqueue(ctx, withHash(newTestItem("target-nosess", "mgr-1"), "hash-A", "")))
	require.NoError(t, store.Enqueue(ctx, withHash(newTestItem("other-nosess", "mgr-1"), "hash-A", "")))

	cascaded, err := store.DenyCascade(ctx, "target-nosess", "no", "principal-1")
	require.NoError(t, err)
	assert.Empty(t, cascaded, "empty session must disable cascading")

	got, err := store.Get(ctx, "other-nosess")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusPending, got.Status)

	// Mixed: target HAS a session, lookalike has none — still no cascade.
	require.NoError(t, store.Enqueue(ctx, withHash(newTestItem("target-sess", "mgr-1"), "hash-B", "sess-1")))
	require.NoError(t, store.Enqueue(ctx, withHash(newTestItem("other-nosess-2", "mgr-1"), "hash-B", "")))

	cascaded, err = store.DenyCascade(ctx, "target-sess", "no", "principal-1")
	require.NoError(t, err)
	assert.Empty(t, cascaded, "non-empty session must not cascade into empty-session items")

	got, err = store.Get(ctx, "other-nosess-2")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusPending, got.Status)
}

func TestDenyCascade_SkipsExpiredDuplicates(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	withHash := func(item *actioninbox.InboxItem, hash, session string) *actioninbox.InboxItem {
		item.ContentHash = hash
		item.Context = map[string]any{actioninbox.SessionContextKey: session}
		return item
	}

	require.NoError(t, store.Enqueue(ctx, withHash(newTestItem("target", "mgr-1"), "hash-A", "sess-1")))
	require.NoError(t, store.Enqueue(ctx, withHash(newTestItem("live-dup", "mgr-1"), "hash-A", "sess-1")))
	// Same hash + session but already logically expired: it must remain an
	// expired audit record, never a cascade-denied one.
	expired := withHash(newTestItem("expired-dup", "mgr-1"), "hash-A", "sess-1")
	expired.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	expired.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	require.NoError(t, store.Enqueue(ctx, expired))

	cascaded, err := store.DenyCascade(ctx, "target", "no", "principal-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"live-dup"}, cascaded, "expired duplicates must not be cascaded")

	got, err := store.Get(ctx, "expired-dup")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusExpired, got.Status, "expired item must read as EXPIRED, not DENIED")
	assert.Nil(t, got.Denial, "expired item must not carry a denial record")
}

func TestDenyCascade_ExpiredTargetDoesNotCascade(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	withHash := func(item *actioninbox.InboxItem, hash, session string) *actioninbox.InboxItem {
		item.ContentHash = hash
		item.Context = map[string]any{actioninbox.SessionContextKey: session}
		return item
	}

	// Logically expired TARGET plus a live matching request: the expired
	// target must not be denied and must not cascade into the live item.
	expiredTarget := withHash(newTestItem("expired-target", "mgr-1"), "hash-A", "sess-1")
	expiredTarget.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	expiredTarget.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	require.NoError(t, store.Enqueue(ctx, expiredTarget))
	require.NoError(t, store.Enqueue(ctx, withHash(newTestItem("live-dup", "mgr-1"), "hash-A", "sess-1")))

	_, err := store.DenyCascade(ctx, "expired-target", "no", "principal-1")
	require.Error(t, err, "expired target must reject the cascade")
	assert.Contains(t, err.Error(), "expired")

	target, err := store.Get(ctx, "expired-target")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusExpired, target.Status, "expired target must read as EXPIRED, not DENIED")
	assert.Nil(t, target.Denial, "expired target must not carry a denial record")

	live, err := store.Get(ctx, "live-dup")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusPending, live.Status, "live matching request must be unaffected")
	assert.Nil(t, live.Denial)
}

func TestRouteSlices_GetAndEnqueueReturnDeepCopy(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	item := newTestItem("item-1", "mgr-1")
	item.ContentHash = "hash-A"
	item.Context = map[string]any{actioninbox.SessionContextKey: "sess-1"}
	item.Route = actioninbox.ApprovalRoute{
		RouteType:   "single_human",
		ApproverIDs: []string{"approver-1"},
		Quorum:      1,
		TimeoutSecs: 3600,
		OnTimeout:   "deny",
	}
	require.NoError(t, store.Enqueue(ctx, item))

	// Mutating the caller's route slices after Enqueue must not rewrite
	// the stored route (SameApprovalDomain forgery regression).
	item.Route.ApproverIDs[0] = "approver-forged"

	// Mutating the route slices returned by Get must not corrupt the
	// store either.
	got, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	got.Route.ApproverIDs[0] = "approver-forged"

	other := newTestItem("item-2", "mgr-1")
	other.ContentHash = "hash-A"
	other.Context = map[string]any{actioninbox.SessionContextKey: "sess-1"}
	other.Route = actioninbox.ApprovalRoute{
		RouteType:   "single_human",
		ApproverIDs: []string{"approver-1"},
		Quorum:      1,
		TimeoutSecs: 3600,
		OnTimeout:   "deny",
	}
	require.NoError(t, store.Enqueue(ctx, other))

	cascaded, err := store.DenyCascade(ctx, "item-1", "no", "principal-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"item-2"}, cascaded,
		"stored route must be immune to caller mutation of aliased slices")

	again, err := store.Get(ctx, "item-2")
	require.NoError(t, err)
	require.NotNil(t, again.Denial)
	assert.Equal(t, []string{"approver-1"}, again.Route.ApproverIDs,
		"denied item's stored route must retain original approvers")
}

func TestDenyCascade_NeverCrossesApprovalDomains(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	base := func(id string) *actioninbox.InboxItem {
		item := newTestItem(id, "mgr-1")
		item.ContentHash = "hash-A"
		item.Context = map[string]any{actioninbox.SessionContextKey: "sess-1"}
		return item
	}

	require.NoError(t, store.Enqueue(ctx, base("target")))

	// Same hash + session, but each in a DIFFERENT approval domain.
	otherManager := base("other-manager")
	otherManager.ManagerID = "mgr-2"
	require.NoError(t, store.Enqueue(ctx, otherManager))

	otherEmployee := base("other-employee")
	otherEmployee.EmployeeID = "emp-2"
	require.NoError(t, store.Enqueue(ctx, otherEmployee))

	otherRoute := base("other-route")
	otherRoute.Route = actioninbox.ApprovalRoute{RouteType: "dual_control", Quorum: 2, TimeoutSecs: 7200, OnTimeout: "escalate"}
	require.NoError(t, store.Enqueue(ctx, otherRoute))

	// Identical domain: this one MUST cascade.
	sameDomain := base("same-domain")
	require.NoError(t, store.Enqueue(ctx, sameDomain))

	cascaded, err := store.DenyCascade(ctx, "target", "no", "principal-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"same-domain"}, cascaded,
		"cascade must stay inside the target's approval domain")

	for _, id := range []string{"other-manager", "other-employee", "other-route"} {
		got, err := store.Get(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, actioninbox.StatusPending, got.Status, id)
		assert.Nil(t, got.Denial, id)
	}
	got, err := store.Get(ctx, "same-domain")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusDenied, got.Status)
	require.NotNil(t, got.Denial)
	assert.Equal(t, actioninbox.ReasonCascadeRejected, got.Denial.ReasonCode)
}

func TestDenyCascade_TargetWithoutDomainFieldsDoesNotCascade(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	// Target lacks domain-defining fields (no ManagerID/EmployeeID): not
	// comparable, so fail-closed — nothing cascades even to lookalikes.
	target := &actioninbox.InboxItem{
		ItemID:      "target",
		Title:       "domainless",
		ContentHash: "hash-A",
		Context:     map[string]any{actioninbox.SessionContextKey: "sess-1"},
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}
	require.NoError(t, store.Enqueue(ctx, target))

	lookalike := &actioninbox.InboxItem{
		ItemID:      "lookalike",
		Title:       "domainless-2",
		ContentHash: "hash-A",
		Context:     map[string]any{actioninbox.SessionContextKey: "sess-1"},
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}
	require.NoError(t, store.Enqueue(ctx, lookalike))

	cascaded, err := store.DenyCascade(ctx, "target", "no", "principal-1")
	require.NoError(t, err)
	assert.Empty(t, cascaded, "items without comparable domain fields must not cascade")

	got, err := store.Get(ctx, "lookalike")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusPending, got.Status)
}

func TestDenyCascade_NonPendingTargetFails(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	require.NoError(t, store.Enqueue(ctx, newTestItem("item-1", "mgr-1")))
	require.NoError(t, store.Deny(ctx, "item-1", "no", "principal-1"))

	_, err := store.DenyCascade(ctx, "item-1", "no", "principal-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not pending")
}

func TestDenialRecord_JSONRoundTripIsAdditive(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	require.NoError(t, store.Enqueue(ctx, newTestItem("item-1", "mgr-1")))
	require.NoError(t, store.Deny(ctx, "item-1", "feedback text", "principal-1"))

	got, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	// The denial record renders as structured JSON alongside the legacy
	// item shape (additive omitempty field, no schema break).
	raw, err := json.Marshal(got)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"denial"`)
	assert.Contains(t, string(raw), `"schema_version":"`+actioninbox.DenyFeedbackSchemaVersion+`"`)
	assert.Contains(t, string(raw), `"reason_code":"`+actioninbox.ReasonHumanRejected+`"`)
}
