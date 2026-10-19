package jwks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testReassignment(profile, client string) map[string]any {
	return map[string]any{
		"version": "helm.reassignment.v1", "grant_id": "11111111-1111-7111-8111-111111111111",
		"generation": 1, "manifest_digest": "sha256:" + strings.Repeat("a", 64),
		"application_digest": "sha256:" + strings.Repeat("b", 64), "work_item_id": "work-1",
		"recipient": map[string]any{"episode_id": "ep-2", "seat_id": "seat-1", "principal_id": "agt:seat-1",
			"actor_id": "spiffe://helm/control-plane", "profile": profile, "client": client},
	}
}

func TestReassignmentClaimRequiresTheExactEpisodeAndListener(t *testing.T) {
	identity, sign := episodeIdentity(t)
	worker, err := identity.WorkerValidator("helm-gateway-worker:test", WorkerTokenMaxTTLCeiling)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := identity.ExecutorValidator("helm-gateway-executor:test", ExecutorTokenMaxTTLCeiling)
	if err != nil {
		t.Fatal(err)
	}
	ep := map[string]string{"episode_id": "ep-2", "work_item_id": "work-1", "organization_version_id": "v-1"}
	w := testReassignment("worker", "")
	got, err := worker.ValidateAuthorization(sign("helm-gateway-worker:test", time.Hour, ep, jwt.MapClaims{"helm_reassignment": w}))
	if err != nil || got.Reassignment == nil || got.Reassignment.Recipient.Profile != "worker" {
		t.Fatalf("worker reassignment = %+v, %v", got, err)
	}
	e := testReassignment("executor", "codex")
	base := jwt.MapClaims{"helm_executor": map[string]string{"client": "codex"}}
	got, err = executor.ValidateAuthorization(sign("helm-gateway-executor:test", 5*time.Minute, ep, base, jwt.MapClaims{"helm_reassignment": e}))
	if err != nil || got.Reassignment == nil || got.Reassignment.Recipient.Profile != "executor" {
		t.Fatalf("executor reassignment = %+v, %v", got, err)
	}
	if _, err := worker.ValidateAuthorization(sign("helm-gateway-worker:test", time.Hour, ep, jwt.MapClaims{"helm_reassignment": e})); err == nil {
		t.Fatal("worker listener accepted an executor grant")
	}
	if _, err := executor.ValidateAuthorization(sign("helm-gateway-executor:test", 5*time.Minute, ep, base, jwt.MapClaims{"helm_reassignment": w})); err == nil {
		t.Fatal("executor listener accepted a worker grant")
	}
	mutate := func(fn func(map[string]any)) jwt.MapClaims {
		data, _ := json.Marshal(e)
		var copy map[string]any
		_ = json.Unmarshal(data, &copy)
		fn(copy)
		return jwt.MapClaims{"helm_reassignment": copy}
	}
	for name, fields := range map[string]jwt.MapClaims{
		"other work":   mutate(func(m map[string]any) { m["work_item_id"] = "work-else" }),
		"other seat":   mutate(func(m map[string]any) { m["recipient"].(map[string]any)["seat_id"] = "seat-else" }),
		"other actor":  mutate(func(m map[string]any) { m["recipient"].(map[string]any)["actor_id"] = "spiffe://other" }),
		"other client": mutate(func(m map[string]any) { m["recipient"].(map[string]any)["client"] = "claude-code" }),
		"no digest":    mutate(func(m map[string]any) { delete(m, "application_digest") }),
		"unknown":      mutate(func(m map[string]any) { m["attempt_ids"] = []string{} }),
		"nested alias": mutate(func(m map[string]any) { m["recipient"].(map[string]any)["Seat_ID"] = "seat-1" }),
		"duplicate":    {"helm_reassignment": json.RawMessage(`{"version":"helm.reassignment.v1","version":"helm.reassignment.v1"}`)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := executor.ValidateAuthorization(sign("helm-gateway-executor:test", 5*time.Minute, ep, base, fields)); err == nil {
				t.Fatal("unbound claim was accepted")
			}
		})
	}
}
