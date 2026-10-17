package jwks

// quantum_posture: tests classical RS256 JWT verification of continuation
// claims; no post-quantum signature or protection is claimed.

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testContinuation(now time.Time) map[string]any {
	return map[string]any{
		"version": "helm.continuation.v1", "handoff_ref": "cp:executor-continuation:00000000-0000-7000-8000-000000000010",
		"receipt_digest": "sha256:" + strings.Repeat("a", 64), "commitment_id": "commit-1",
		"plan_digest": strings.Repeat("b", 64), "authority_revision": 1, "terms_digest": "sha256:" + strings.Repeat("c", 64),
		// Commit may carry subsecond precision while JWT iat is whole seconds.
		"handoff_recorded_at": now.Add(300 * time.Millisecond).Format(time.RFC3339Nano),
		"tenant_id":           "tenant-a", "workspace_id": "ws-a", "organization_id": "org-1",
		"work_item_id": "work-1", "organization_version_id": "v-1",
		"successor": map[string]any{"episode_id": "ep-2", "seat_id": "seat-1", "principal_id": "agt:seat-1", "actor_id": "spiffe://helm/control-plane"},
		"sources": []any{
			map[string]any{"episode_id": "ep-empty", "seat_id": "seat-1", "principal_id": "agt:seat-1", "actor_id": "",
				"admissible_until": nil, "settled_before": nil, "attempt_ids": []string{}},
			map[string]any{"episode_id": "ep-1", "seat_id": "seat-1", "principal_id": "agt:seat-1", "actor_id": "spiffe://helm/control-plane",
				"admissible_until": now.Add(-40 * time.Second).Format(time.RFC3339), "settled_before": now.Add(-20 * time.Second).Format(time.RFC3339),
				"attempt_ids": []string{"00000000-0000-7000-8000-000000000001"}},
		},
	}
}

func TestExecutorContinuationClaimIsClosedAndBound(t *testing.T) {
	identity, sign := episodeIdentity(t)
	executor, err := identity.ExecutorValidator("helm-gateway-executor:test", ExecutorTokenMaxTTLCeiling)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := identity.WorkerValidator("helm-gateway-worker:test", WorkerTokenMaxTTLCeiling)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ep := map[string]string{"episode_id": "ep-2", "work_item_id": "work-1", "organization_version_id": "v-1"}
	base := jwt.MapClaims{"helm_executor": map[string]string{"client": "codex"}, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	grant := testContinuation(now)
	valid := sign("helm-gateway-executor:test", 5*time.Minute, ep, base, jwt.MapClaims{"helm_continuation": grant})
	got, err := executor.ValidateAuthorization(valid)
	if err != nil || got.Continuation == nil || len(got.Continuation.Sources) != 2 {
		t.Fatalf("valid signed continuation: %+v %v", got, err)
	}
	if _, err := worker.ValidateAuthorization(sign("helm-gateway-worker:test", time.Hour, ep, jwt.MapClaims{"helm_continuation": grant})); err == nil {
		t.Fatal("internal worker accepted a continuation grant")
	}
	mutate := func(fn func(map[string]any)) jwt.MapClaims {
		data, _ := json.Marshal(grant)
		var copy map[string]any
		_ = json.Unmarshal(data, &copy)
		fn(copy)
		return jwt.MapClaims{"helm_continuation": copy}
	}
	cases := map[string]jwt.MapClaims{
		"wrong tenant":                 mutate(func(c map[string]any) { c["tenant_id"] = "foreign" }),
		"wrong work":                   mutate(func(c map[string]any) { c["work_item_id"] = "work-else" }),
		"wrong successor actor":        mutate(func(c map[string]any) { c["successor"].(map[string]any)["actor_id"] = "spiffe://other" }),
		"different seat":               mutate(func(c map[string]any) { c["sources"].([]any)[1].(map[string]any)["seat_id"] = "seat-2" }),
		"attempt without source actor": mutate(func(c map[string]any) { c["sources"].([]any)[1].(map[string]any)["actor_id"] = "" }),
		"omitted empty source actor":   mutate(func(c map[string]any) { delete(c["sources"].([]any)[0].(map[string]any), "actor_id") }),
		"reused attempt": mutate(func(c map[string]any) {
			c["sources"].([]any)[0].(map[string]any)["attempt_ids"] = []string{"00000000-0000-7000-8000-000000000001"}
		}),
		"missing record":       mutate(func(c map[string]any) { delete(c, "handoff_recorded_at") }),
		"missing sources":      mutate(func(c map[string]any) { c["sources"] = []any{} }),
		"no retained attempts": mutate(func(c map[string]any) { c["sources"] = []any{c["sources"].([]any)[0]} }),
		"old bearer not drained": mutate(func(c map[string]any) {
			c["sources"].([]any)[1].(map[string]any)["admissible_until"] = now.Format(time.RFC3339)
		}),
		"over claim cap": mutate(func(c map[string]any) {
			sources := c["sources"].([]any)
			for n := 0; n < 14; n++ {
				sources = append(sources, map[string]any{
					"episode_id": "ep-extra-" + strconv.Itoa(n), "seat_id": "seat-1", "principal_id": "agt:seat-1",
					"actor_id": strings.Repeat("a", 240), "admissible_until": nil, "settled_before": nil,
					"attempt_ids": []string{},
				})
			}
			c["sources"] = sources
		}),
		"duplicate claim member": {"helm_continuation": json.RawMessage(`{"version":"helm.continuation.v1","version":"helm.continuation.v1"}`)},
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := executor.ValidateAuthorization(sign("helm-gateway-executor:test", 5*time.Minute, ep, base, fields)); err == nil {
				t.Fatal("accepted an unbound continuation")
			}
		})
	}
}
