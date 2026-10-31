package runtime

// quantum_posture: real local listeners verify disposable classical RS256
// tokens against TLS JWKS. The unreachable ledger makes this route/auth proof.

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	"github.com/golang-jwt/jwt/v5"
)

func executorHostContinuation(now time.Time) *jwks.ContinuationClaim {
	until, settled := now.Add(-40*time.Second), now.Add(-20*time.Second)
	return &jwks.ContinuationClaim{
		Version: "helm.continuation.v1", HandoffRef: "cp:executor-continuation:00000000-0000-7000-8000-000000000010",
		ReceiptDigest: "sha256:" + strings.Repeat("a", 64), HandoffRecordedAt: now.Add(-time.Second),
		TenantID: "tenant-a", WorkspaceID: "ws-a", OrganizationID: "org-1", WorkItemID: "work-1", OrganizationVersionID: "v-1",
		CommitmentID: "commit-1", PlanDigest: strings.Repeat("b", 64), AuthorityRevision: 1, TermsDigest: "sha256:" + strings.Repeat("c", 64),
		Successor: jwks.ContinuationSuccessor{EpisodeID: "ep-2", SeatID: "seat-1", PrincipalID: "agt:seat-1", ActorID: "spiffe://helm/control-plane"},
		Sources:   []jwks.ContinuationSource{{EpisodeID: "ep-1", SeatID: "seat-1", PrincipalID: "agt:seat-1", ActorID: "spiffe://helm/control-plane", AdmissibleUntil: &until, SettledBefore: &settled, AttemptIDs: []string{"00000000-0000-7000-8000-000000000001"}}},
	}
}

func TestServeExecutorHostNormalAndContinuationRoutes(t *testing.T) {
	identity, sign := jwksServer(t)
	private, worker, executor := freeAddress(t), freeAddress(t), freeAddress(t)
	values := with(identity, map[string]string{
		"HELM_GATEWAY_DATABASE_URL":      "postgres://127.0.0.1:1/none?sslmode=disable",
		"HELM_GATEWAY_MODEL_ROUTES_FILE": routesFile(t),
		"HELM_GATEWAY_WORKER_AUDIENCE":   "helm-gateway-worker:test",
		"HELM_GATEWAY_EXECUTOR_AUDIENCE": "helm-gateway-executor:test",
	})
	startServe(t, []string{"--dev-insecure-listen", private, "--worker-listen", worker, "--executor-listen", executor}, values)
	episode := map[string]string{"episode_id": "ep-2", "work_item_id": "work-1", "organization_version_id": "v-1"}
	request := func(base, path, token string) (int, string) {
		t.Helper()
		method, body := http.MethodGet, ""
		if path == "/mcp" {
			method, body = http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"codex","version":"1"}}}`
		}
		req, err := http.NewRequest(method, "http://"+base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(raw)
	}
	for _, continuation := range []bool{false, true} {
		for _, host := range []string{"", "console-runner", "unknown"} {
			marker := map[string]string{"client": "codex"}
			if host != "" {
				marker["host"] = host
			}
			now := time.Now().UTC().Truncate(time.Second)
			fields := jwt.MapClaims{"helm_executor": marker, "scope": "helm.gateway.propose helm.gateway.read", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
			if continuation {
				fields["helm_continuation"] = executorHostContinuation(now)
			}
			token := sign("helm-gateway-executor:test", 5*time.Minute, episode, fields)
			for _, path := range []string{"/mcp", "/v1/models"} {
				code, body := request(executor, path, token)
				if host == "unknown" {
					if code != http.StatusUnauthorized && code != http.StatusForbidden {
						t.Fatalf("unknown host passed auth: continuation=%t %s %d %s", continuation, path, code, body)
					}
				} else if path == "/mcp" {
					if code != http.StatusOK || !strings.Contains(body, `"protocolVersion":"2025-11-25"`) {
						t.Fatalf("MCP host=%q continuation=%t: %d %s", host, continuation, code, body)
					}
				} else if code != http.StatusServiceUnavailable || !strings.Contains(body, "ledger_unavailable") {
					t.Fatalf("model auth host=%q continuation=%t: %d %s", host, continuation, code, body)
				}
				for _, other := range []string{private, worker} {
					if path == "/mcp" && other == private {
						continue
					}
					if code, body := request(other, path, token); code != http.StatusUnauthorized && code != http.StatusForbidden {
						t.Fatalf("executor crossed listener: host=%q continuation=%t %s %d %s", host, continuation, path, code, body)
					}
				}
			}
		}
	}
}
