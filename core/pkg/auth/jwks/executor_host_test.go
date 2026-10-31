package jwks

// quantum_posture: disposable RS256 signatures and local JWKS fixtures test
// classical episode authentication. Host provenance grants no new authority.

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestExecutorHostSignedNormalAndContinuationTokens(t *testing.T) {
	identity, sign := episodeIdentity(t)
	executor, err := identity.ExecutorValidator("helm-gateway-executor:test", ExecutorTokenMaxTTLCeiling)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := identity.WorkerValidator("helm-gateway-worker:test", WorkerTokenMaxTTLCeiling)
	if err != nil {
		t.Fatal(err)
	}
	episode := map[string]string{"episode_id": "ep-2", "work_item_id": "work-1", "organization_version_id": "v-1"}
	for _, continuation := range []bool{false, true} {
		for _, client := range []string{"claude-code", "codex", "openclaw"} {
			for _, shape := range []struct{ marker, host string }{
				{fmt.Sprintf(`{"client":%q}`, client), ""},
				{fmt.Sprintf(`{"client":%q,"host":"console-runner"}`, client), "console-runner"},
				{fmt.Sprintf(`{"host":"console-runner","client":%q}`, client), "console-runner"},
			} {
				t.Run(fmt.Sprintf("continuation=%t/client=%s/marker=%s", continuation, client, shape.marker), func(t *testing.T) {
					now := time.Now().UTC().Truncate(time.Second)
					fields := jwt.MapClaims{"helm_executor": json.RawMessage(shape.marker), "scope": "helm.gateway.propose helm.gateway.read", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
					if continuation {
						fields["helm_continuation"] = testContinuation(now)
					}
					raw := sign("helm-gateway-executor:test", 5*time.Minute, episode, fields)
					got, err := executor.ValidateAuthorization(raw)
					if err != nil || got.Executor == nil || got.Executor.Client != client {
						t.Fatalf("signed executor provenance rejected: %+v %v", got, err)
					}
					marker, err := json.Marshal(got.Executor)
					if err != nil {
						t.Fatal(err)
					}
					want := fmt.Sprintf(`{"client":%q}`, client)
					if shape.host != "" {
						want = fmt.Sprintf(`{"client":%q,"host":%q}`, client, shape.host)
					}
					if string(marker) != want {
						t.Fatalf("verified provenance lost: %s != %s", marker, want)
					}
					if got.RegisteredClaims.Subject != "agt:seat-1" || got.Actor != identity.Actor || got.TenantID != "tenant-a" || got.WorkspaceID != "ws-a" || (got.Continuation != nil) != continuation {
						t.Fatalf("host changed identity or continuation: %+v", got)
					}
					if _, err := worker.ValidateAuthorization(raw); err == nil {
						t.Fatal("executor token admitted to worker listener")
					}
				})
			}
		}
	}
}

func TestExecutorHostSignedMarkerRejectsMalformedProvenance(t *testing.T) {
	identity, sign := episodeIdentity(t)
	executor, err := identity.ExecutorValidator("helm-gateway-executor:test", ExecutorTokenMaxTTLCeiling)
	if err != nil {
		t.Fatal(err)
	}
	episode := map[string]string{"episode_id": "ep-2", "work_item_id": "work-1", "organization_version_id": "v-1"}
	for _, marker := range []string{
		`{"client":"codex","host":"unknown"}`, `{"client":"codex","host":""}`,
		`{"client":"codex","host":null}`, `{"client":"codex","host":1}`,
		`{"client":"codex","host":"Console-Runner"}`, `{"client":"codex","host":"console-runner "}`,
		`{"client":"codex","Host":"console-runner"}`, `{"Client":"codex","host":"console-runner"}`,
		`{"client":"codex","host":"console-runner","host":"console-runner"}`,
		`{"client":"codex","client":"codex","host":"console-runner"}`,
		`{"host":"console-runner"}`, `{"client":null,"host":"console-runner"}`,
		`{"client":"codex","host":"console-runner","grant":"all"}`,
	} {
		for _, continuation := range []bool{false, true} {
			now := time.Now().UTC().Truncate(time.Second)
			fields := jwt.MapClaims{"helm_executor": json.RawMessage(marker), "scope": "helm.gateway.propose helm.gateway.read", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
			if continuation {
				fields["helm_continuation"] = testContinuation(now)
			}
			if _, err := executor.ValidateAuthorization(sign("helm-gateway-executor:test", 5*time.Minute, episode, fields)); err == nil {
				t.Fatalf("signed invalid provenance accepted: continuation=%t %s", continuation, marker)
			}
		}
	}
}
