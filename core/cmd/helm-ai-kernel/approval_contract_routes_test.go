package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

func TestMCPAuthorizeCallAPIFailsClosedWithUnverifiedPersistedApproval(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	// Legacy persisted state is opaque local metadata, not approval authority.
	// The registry must quarantine it before the route hydrates the firewall.
	surfaces := boundarypkg.NewSurfaceRegistry(time.Now)
	if _, err := surfaces.PutMCPServer(mcppkg.ServerQuarantineRecord{
		ServerID:          "api-fixture",
		ToolNames:         []string{"local.echo"},
		ApprovedToolNames: []string{"local.echo"},
		Risk:              "high",
		State:             mcppkg.QuarantineApproved,
		DiscoveredAt:      time.Now().UTC(),
		ApprovedAt:        time.Now().UTC(),
		ApprovedBy:        "user:alice",
		ApprovalReceiptID: "approval-r1",
		Reason:            "reviewed",
	}); err != nil {
		t.Fatalf("seed approved mcp server: %v", err)
	}
	persisted, ok := surfaces.GetMCPServer("api-fixture")
	if !ok || persisted.State != mcppkg.QuarantineQuarantined {
		t.Fatalf("unverified approval persisted as executable state: found=%t record=%+v", ok, persisted)
	}
	svc.BoundarySurfaces = surfaces
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"text": map[string]any{"type": "string"},
		},
		"required": []string{"text"},
	}
	hash, err := mcppkg.ToolSchemaHash(mcppkg.ToolRef{Name: "local.echo", Schema: schema})
	if err != nil {
		t.Fatalf("schema hash: %v", err)
	}

	unknownServer := postMCPAuthorizeForTest(t, mux, map[string]any{
		"server_id":          "api-unknown-server",
		"tool_name":          "local.echo",
		"args_hash":          "sha256:unknown-server",
		"tool_schema":        schema,
		"pinned_schema_hash": hash,
	}, http.StatusForbidden)
	if unknownServer["verdict"] != "DENY" && unknownServer["verdict"] != "ESCALATE" {
		t.Fatalf("unknown server verdict = %+v", unknownServer)
	}

	unknownTool := postMCPAuthorizeForTest(t, mux, map[string]any{
		"server_id": "api-fixture",
		"tool_name": "local.missing",
		"args_hash": "sha256:unknown-tool",
	}, http.StatusForbidden)
	if unknownTool["verdict"] != "DENY" && unknownTool["verdict"] != "ESCALATE" {
		t.Fatalf("unknown tool verdict = %+v", unknownTool)
	}

	missingPin := postMCPAuthorizeForTest(t, mux, map[string]any{
		"server_id":   "api-fixture",
		"tool_name":   "local.echo",
		"args_hash":   "sha256:missing-pin",
		"tool_schema": schema,
	}, http.StatusForbidden)
	if missingPin["verdict"] != "DENY" && missingPin["verdict"] != "ESCALATE" {
		t.Fatalf("missing pin verdict = %+v", missingPin)
	}

	unverified := postMCPAuthorizeForTest(t, mux, map[string]any{
		"server_id":          "api-fixture",
		"tool_name":          "local.echo",
		"args_hash":          "sha256:pinned-allow",
		"tool_schema":        schema,
		"pinned_schema_hash": hash,
	}, http.StatusForbidden)
	if unverified["verdict"] == "ALLOW" {
		t.Fatalf("unverified persisted approval authorized dispatch: %+v", unverified)
	}
	if unverified["reason_code"] != string(contracts.ReasonApprovalRequired) {
		t.Fatalf("unverified approval reason = %+v", unverified)
	}
	if unverified["record_hash"] == "" {
		t.Fatal("fail-closed record_hash missing")
	}
}

// routeApprovalAssertionVerifier is a test double for the credential verifier
// consulted by the WebAuthn assert route.
type routeApprovalAssertionVerifier struct {
	err error
}

func (v *routeApprovalAssertionVerifier) VerifyApprovalAssertion(contracts.ApprovalWebAuthnChallenge, contracts.ApprovalWebAuthnAssertion) error {
	return v.err
}

func webAuthnRouteChallengeID(t *testing.T, mux *http.ServeMux, approvalID string) string {
	t.Helper()
	now := time.Now().UTC()
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals", strings.NewReader(fmt.Sprintf(`{"approval_id":%q,"subject":"mcp:srv","action":"mcp.approve","requested_by":"agent:test","quorum":1,"timelock_until":%q,"expires_at":%q}`, approvalID, now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano))))
	authorizeTestRequest(createReq)
	createRec := httptest.NewRecorder()
	mux.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create approval status=%d body=%s", createRec.Code, createRec.Body.String())
	}

	challengeReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+approvalID+"/webauthn/challenge", strings.NewReader(`{"method":"passkey","ttl_ms":60000}`))
	authorizeTestRequest(challengeReq)
	challengeRec := httptest.NewRecorder()
	mux.ServeHTTP(challengeRec, challengeReq)
	if challengeRec.Code != http.StatusCreated {
		t.Fatalf("challenge status=%d body=%s", challengeRec.Code, challengeRec.Body.String())
	}
	var challenge map[string]any
	if err := json.Unmarshal(challengeRec.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	challengeID, _ := challenge["challenge_id"].(string)
	if challengeID == "" {
		t.Fatalf("challenge missing id: %+v", challenge)
	}
	return challengeID
}

func TestApprovalRouteRequiresAbsoluteWindow(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/approvals", strings.NewReader(`{"approval_id":"approval-relative","subject":"mcp:srv","action":"mcp.approve","requested_by":"agent:test","timelock_ms":60000,"expires_in_ms":3600000}`))
	authorizeTestRequest(request)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "timelock_until and expires_at") {
		t.Fatalf("relative approval window status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	now := time.Now().UTC()
	timelockUntil := now.Add(-time.Minute)
	expiresAt := now.Add(time.Hour)
	request = httptest.NewRequest(http.MethodPost, "/api/v1/approvals", strings.NewReader(fmt.Sprintf(`{"approval_id":"approval-absolute","subject":"mcp:srv","action":"mcp.approve","requested_by":"agent:test","timelock_until":%q,"expires_at":%q}`, timelockUntil.Format(time.RFC3339Nano), expiresAt.Format(time.RFC3339Nano))))
	authorizeTestRequest(request)
	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("absolute approval window status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var approval contracts.ApprovalCeremony
	if err := json.Unmarshal(recorder.Body.Bytes(), &approval); err != nil {
		t.Fatal(err)
	}
	if !approval.TimelockUntil.Equal(timelockUntil) || !approval.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("approval window = (%s,%s), want (%s,%s)", approval.TimelockUntil, approval.ExpiresAt, timelockUntil, expiresAt)
	}
}

func TestApprovalWebAuthnAssertFailsClosedWithoutVerifier(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	challengeID := webAuthnRouteChallengeID(t, mux, "approval-webauthn")

	assertReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approval-webauthn/webauthn/assert", strings.NewReader(fmt.Sprintf(`{"challenge_id":%q,"actor":"user:alice","assertion":"signed-client-data","receipt_id":"rcpt-approval"}`, challengeID)))
	authorizeTestRequest(assertReq)
	assertRec := httptest.NewRecorder()
	mux.ServeHTTP(assertRec, assertReq)
	if assertRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("assert status=%d body=%s", assertRec.Code, assertRec.Body.String())
	}
	if contentType := assertRec.Header().Get("Content-Type"); !strings.Contains(contentType, "application/problem+json") {
		t.Fatalf("assert content type = %q", contentType)
	}
	var problem struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(assertRec.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Title != "Approval verification unavailable" || !strings.Contains(problem.Detail, boundarypkg.ErrApprovalVerificationUnavailable.Error()) {
		t.Fatalf("assert problem = %+v", problem)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	authorizeTestRequest(listReq)
	listRec := httptest.NewRecorder()
	mux.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK || strings.Contains(listRec.Body.String(), `"approval_id":"approval-webauthn","state":"approved"`) {
		t.Fatalf("unverified assertion minted approval authority: status=%d body=%s", listRec.Code, listRec.Body.String())
	}
}

func TestApprovalWebAuthnAssertRejectsFailedVerification(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	registry := boundarypkg.NewSurfaceRegistry(time.Now)
	registry.SetApprovalAssertionVerifier(&routeApprovalAssertionVerifier{err: fmt.Errorf("signature does not match registered credential")})
	svc.BoundarySurfaces = registry
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	challengeID := webAuthnRouteChallengeID(t, mux, "approval-webauthn-reject")

	assertReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approval-webauthn-reject/webauthn/assert", strings.NewReader(fmt.Sprintf(`{"challenge_id":%q,"actor":"user:alice","assertion":"garbage","receipt_id":"rcpt-approval"}`, challengeID)))
	authorizeTestRequest(assertReq)
	assertRec := httptest.NewRecorder()
	mux.ServeHTTP(assertRec, assertReq)
	if assertRec.Code != http.StatusBadRequest || !strings.Contains(assertRec.Body.String(), "approval assertion rejected") {
		t.Fatalf("rejected assert status=%d body=%s", assertRec.Code, assertRec.Body.String())
	}
}

func TestApprovalRoutesSupportWebAuthnChallengeAssertionWithVerifier(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	registry := boundarypkg.NewSurfaceRegistry(time.Now)
	registry.SetApprovalAssertionVerifier(&routeApprovalAssertionVerifier{})
	svc.BoundarySurfaces = registry
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	challengeID := webAuthnRouteChallengeID(t, mux, "approval-webauthn")

	assertReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approval-webauthn/webauthn/assert", strings.NewReader(fmt.Sprintf(`{"challenge_id":%q,"actor":"user:alice","assertion":"signed-client-data","receipt_id":"rcpt-approval"}`, challengeID)))
	authorizeTestRequest(assertReq)
	assertRec := httptest.NewRecorder()
	mux.ServeHTTP(assertRec, assertReq)
	if assertRec.Code != http.StatusOK {
		t.Fatalf("assert status=%d body=%s", assertRec.Code, assertRec.Body.String())
	}
	var approval map[string]any
	if err := json.Unmarshal(assertRec.Body.Bytes(), &approval); err != nil {
		t.Fatal(err)
	}
	if approval["state"] != "approved" || approval["auth_method"] != "passkey" {
		t.Fatalf("approval did not bind passkey assertion: %+v", approval)
	}
}

func TestApprovalRouteDerivesActorAndRejectsStaleCeremony(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	registry := boundarypkg.NewSurfaceRegistry(time.Now)
	svc.BoundarySurfaces = registry
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	now := time.Now().UTC()
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals", strings.NewReader(fmt.Sprintf(`{"approval_id":"approval-raw-admin","subject":"mcp:srv","action":"mcp.approve","requested_by":"agent:test","quorum":1,"timelock_until":%q,"expires_at":%q}`, now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano))))
	authorizeTestRequest(createReq)
	createRec := httptest.NewRecorder()
	mux.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create approval status=%d body=%s", createRec.Code, createRec.Body.String())
	}
	var created contracts.ApprovalCeremony
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	transitionReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approval-raw-admin/approve", strings.NewReader(fmt.Sprintf(`{"actor":"user:attacker","expected_ceremony_hash":%q,"reason":"reviewed"}`, created.CeremonyHash)))
	authorizeTestRequest(transitionReq)
	// The raw admin path must ignore both body and tenant-header identities.
	transitionReq.Header.Set(principalHeader, "user:attacker")
	transitionRec := httptest.NewRecorder()
	mux.ServeHTTP(transitionRec, transitionReq)
	if transitionRec.Code != http.StatusOK {
		t.Fatalf("transition approval status=%d body=%s", transitionRec.Code, transitionRec.Body.String())
	}
	var approval contracts.ApprovalCeremony
	if err := json.Unmarshal(transitionRec.Body.Bytes(), &approval); err != nil {
		t.Fatal(err)
	}
	if approval.State != contracts.ApprovalCeremonyAllowed || len(approval.Approvers) != 1 || approval.Approvers[0] != "system-admin" {
		t.Fatalf("raw shared-admin transition trusted caller identity: %+v", approval)
	}

	staleReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approval-raw-admin/revoke", strings.NewReader(fmt.Sprintf(`{"expected_ceremony_hash":%q,"reason":"stale"}`, created.CeremonyHash)))
	authorizeTestRequest(staleReq)
	staleRec := httptest.NewRecorder()
	mux.ServeHTTP(staleRec, staleReq)
	if staleRec.Code != http.StatusConflict || !strings.Contains(staleRec.Body.String(), "refresh and review again") {
		t.Fatalf("stale transition status=%d body=%s", staleRec.Code, staleRec.Body.String())
	}

	missingHashReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approval-raw-admin/revoke", strings.NewReader(`{"reason":"missing hash"}`))
	authorizeTestRequest(missingHashReq)
	missingHashRec := httptest.NewRecorder()
	mux.ServeHTTP(missingHashRec, missingHashReq)
	if missingHashRec.Code != http.StatusPreconditionRequired || !strings.Contains(missingHashRec.Body.String(), "expected_ceremony_hash") {
		t.Fatalf("missing-hash transition status=%d body=%s", missingHashRec.Code, missingHashRec.Body.String())
	}
	approvals := registry.ListApprovals()
	var transitioned *contracts.ApprovalCeremony
	for index := range approvals {
		if approvals[index].ApprovalID == created.ApprovalID {
			transitioned = &approvals[index]
			break
		}
	}
	if transitioned == nil || transitioned.State != contracts.ApprovalCeremonyAllowed {
		t.Fatalf("missing ceremony hash changed approval state: %+v", approvals)
	}
}

func postMCPAuthorizeForTest(t *testing.T, mux *http.ServeMux, body map[string]any, wantStatus int) map[string]any {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/authorize-call", bytes.NewReader(data))
	authorizeTestRequest(req)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("authorize status=%d want=%d body=%s", rec.Code, wantStatus, rec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
