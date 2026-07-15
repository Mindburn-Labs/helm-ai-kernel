package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	launchregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	trustregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust/registry"
)

func apiCoverageTime() time.Time {
	return time.Date(2026, 5, 22, 9, 0, 0, 0, time.UTC)
}

func apiCoverageDecision(id string) contracts.DecisionRequest {
	return contracts.DecisionRequest{
		RequestID: id,
		Kind:      contracts.DecisionKindApproval,
		Title:     "Approve deployment",
		Options: []contracts.DecisionOption{
			{ID: "approve", Label: "Approve"},
			{ID: "deny", Label: "Deny"},
		},
		Priority:  contracts.DecisionPriorityNormal,
		Status:    contracts.DecisionStatusPending,
		CreatedAt: apiCoverageTime(),
	}
}

func TestCoverageApproveHandlerBranches(t *testing.T) {
	now := apiCoverageTime()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	handler := NewApproveHandler([]string{pubHex}).WithClock(func() time.Time { return now })

	pending := &contracts.ApprovalRequest{
		RequestID:  "approval-1",
		IntentHash: "sha256:intent",
		IntentID:   "intent-1",
		ToolName:   "deploy",
		RiskLevel:  "HIGH",
		Status:     contracts.ApprovalPending,
		CreatedAt:  now.Add(-time.Minute),
		ExpiresAt:  now.Add(time.Hour),
	}
	handler.RegisterPendingApproval(pending)
	if got := handler.GetPendingApprovals(); len(got) != 1 || got[0].IntentHash != pending.IntentHash {
		t.Fatalf("pending approvals = %+v", got)
	}

	receipt := contracts.ApprovalReceipt{
		IntentHash: pending.IntentHash,
		PlanHash:   "sha256:plan",
		PolicyHash: "sha256:policy",
		Nonce:      "nonce-1",
		ApproverID: "operator",
		PublicKey:  pubHex,
	}
	message := fmt.Sprintf("HELM/Approval/v1:%s:%s:%s:%s", receipt.PlanHash, receipt.PolicyHash, receipt.IntentHash, receipt.Nonce)
	receipt.Signature = hex.EncodeToString(ed25519.Sign(priv, []byte(message)))

	for name, tc := range map[string]struct {
		method string
		body   string
		want   int
	}{
		"method not allowed": {method: http.MethodGet, body: `{}`, want: http.StatusMethodNotAllowed},
		"invalid json":       {method: http.MethodPost, body: `{`, want: http.StatusBadRequest},
		"missing fields":     {method: http.MethodPost, body: `{"intent_hash":"sha256:intent"}`, want: http.StatusBadRequest},
		"not found":          {method: http.MethodPost, body: `{"intent_hash":"sha256:missing","public_key":"` + pubHex + `","signature":"00"}`, want: http.StatusNotFound},
		"invalid public key": {method: http.MethodPost, body: `{"intent_hash":"sha256:intent","public_key":"abc","signature":"00"}`, want: http.StatusBadRequest},
		"invalid signature":  {method: http.MethodPost, body: `{"intent_hash":"sha256:intent","public_key":"` + pubHex + `","signature":"zz"}`, want: http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, "/api/v1/kernel/approve", strings.NewReader(tc.body))
			handler.HandleApprove(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	badSignature := receipt
	badSignature.Signature = hex.EncodeToString(make([]byte, ed25519.SignatureSize))
	body, _ := json.Marshal(badSignature)
	rec := httptest.NewRecorder()
	handler.HandleApprove(rec, httptest.NewRequest(http.MethodPost, "/api/v1/kernel/approve", bytes.NewReader(body)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad signature status = %d, want 403", rec.Code)
	}

	conflict := *pending
	conflict.IntentHash = "sha256:conflict"
	conflict.Status = contracts.ApprovalApproved
	handler.RegisterPendingApproval(&conflict)
	conflictReceipt := receipt
	conflictReceipt.IntentHash = conflict.IntentHash
	body, _ = json.Marshal(conflictReceipt)
	rec = httptest.NewRecorder()
	handler.HandleApprove(rec, httptest.NewRequest(http.MethodPost, "/api/v1/kernel/approve", bytes.NewReader(body)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("conflict status = %d, want 409", rec.Code)
	}

	expired := *pending
	expired.IntentHash = "sha256:expired"
	expired.ExpiresAt = now.Add(-time.Second)
	handler.RegisterPendingApproval(&expired)
	expiredReceipt := receipt
	expiredReceipt.IntentHash = expired.IntentHash
	body, _ = json.Marshal(expiredReceipt)
	rec = httptest.NewRecorder()
	handler.HandleApprove(rec, httptest.NewRequest(http.MethodPost, "/api/v1/kernel/approve", bytes.NewReader(body)))
	if rec.Code != http.StatusGone {
		t.Fatalf("expired status = %d, want 410", rec.Code)
	}
	if expired.Status != contracts.ApprovalExpired {
		t.Fatalf("expired approval status = %s", expired.Status)
	}
}

type apiCoverageDecisionStore struct {
	decisions []contracts.DecisionRequest
	decision  *contracts.DecisionRequest
	listErr   error
	createErr error
	updateErr error
	getErr    error
}

func (s *apiCoverageDecisionStore) List(_ string, _ contracts.DecisionRequestStatus) ([]contracts.DecisionRequest, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.decisions, nil
}

func (s *apiCoverageDecisionStore) Get(_ string) (*contracts.DecisionRequest, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.decision == nil {
		return nil, errors.New("missing")
	}
	copy := *s.decision
	return &copy, nil
}

func (s *apiCoverageDecisionStore) Create(dr *contracts.DecisionRequest) error {
	if s.createErr != nil {
		return s.createErr
	}
	s.decisions = append(s.decisions, *dr)
	return nil
}

func (s *apiCoverageDecisionStore) Update(dr *contracts.DecisionRequest) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	s.decision = dr
	return nil
}

func TestCoverageDecisionHandlerBranches(t *testing.T) {
	valid := apiCoverageDecision("decision-1")

	for name, tc := range map[string]struct {
		handler *DecisionHandler
		method  string
		path    string
		body    string
		want    int
	}{
		"decisions method": {
			handler: NewDecisionHandler(&apiCoverageDecisionStore{}),
			method:  http.MethodDelete,
			path:    "/api/decisions",
			want:    http.StatusMethodNotAllowed,
		},
		"list store error": {
			handler: NewDecisionHandler(&apiCoverageDecisionStore{listErr: errors.New("list failed")}),
			method:  http.MethodGet,
			path:    "/api/decisions",
			want:    http.StatusInternalServerError,
		},
		"create invalid json": {
			handler: NewDecisionHandler(&apiCoverageDecisionStore{}),
			method:  http.MethodPost,
			path:    "/api/decisions",
			body:    `{`,
			want:    http.StatusBadRequest,
		},
		"create store error": {
			handler: NewDecisionHandler(&apiCoverageDecisionStore{createErr: errors.New("create failed")}),
			method:  http.MethodPost,
			path:    "/api/decisions",
			body:    marshalAPIValue(t, valid),
			want:    http.StatusInternalServerError,
		},
		"bad resolve path": {
			handler: NewDecisionHandler(&apiCoverageDecisionStore{}),
			method:  http.MethodPost,
			path:    "/api/decisions/decision-1",
			want:    http.StatusNotFound,
		},
		"resolve method": {
			handler: NewDecisionHandler(&apiCoverageDecisionStore{}),
			method:  http.MethodGet,
			path:    "/api/decisions/decision-1/resolve",
			want:    http.StatusMethodNotAllowed,
		},
		"resolve invalid json": {
			handler: NewDecisionHandler(&apiCoverageDecisionStore{decision: &valid}),
			method:  http.MethodPost,
			path:    "/api/decisions/decision-1/resolve",
			body:    `{`,
			want:    http.StatusBadRequest,
		},
		"resolve missing option": {
			handler: NewDecisionHandler(&apiCoverageDecisionStore{decision: &valid}),
			method:  http.MethodPost,
			path:    "/api/decisions/decision-1/resolve",
			body:    `{"resolved_by":"operator"}`,
			want:    http.StatusBadRequest,
		},
		"resolve missing principal": {
			handler: NewDecisionHandler(&apiCoverageDecisionStore{decision: &valid}),
			method:  http.MethodPost,
			path:    "/api/decisions/decision-1/resolve",
			body:    `{"option_id":"approve"}`,
			want:    http.StatusBadRequest,
		},
		"resolve not found": {
			handler: NewDecisionHandler(&apiCoverageDecisionStore{getErr: errors.New("not found")}),
			method:  http.MethodPost,
			path:    "/api/decisions/decision-1/resolve",
			body:    `{"option_id":"approve","resolved_by":"operator"}`,
			want:    http.StatusNotFound,
		},
		"resolve update error": {
			handler: NewDecisionHandler(&apiCoverageDecisionStore{decision: &valid, updateErr: errors.New("update failed")}),
			method:  http.MethodPost,
			path:    "/api/decisions/decision-1/resolve",
			body:    `{"option_id":"approve","resolved_by":"operator"}`,
			want:    http.StatusInternalServerError,
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if strings.HasPrefix(tc.path, "/api/decisions/") {
				tc.handler.HandleDecisionByID(rec, req)
			} else {
				tc.handler.HandleDecisions(rec, req)
			}
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	expired := valid
	expired.RequestID = "expired"
	expired.ExpiresAt = apiCoverageTime().Add(-time.Second)
	store := &apiCoverageDecisionStore{decision: &expired}
	handler := NewDecisionHandler(store)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/decisions/expired/resolve", strings.NewReader(`{"option_id":"approve","resolved_by":"operator"}`))
	handler.HandleDecisionByID(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expired resolve status = %d, want 400", rec.Code)
	}
	if store.decision == nil || store.decision.Status != contracts.DecisionStatusExpired {
		t.Fatalf("expired decision was not persisted: %+v", store.decision)
	}
}

func TestCoverageInMemoryDecisionStoreEdges(t *testing.T) {
	store := NewInMemoryDecisionStore()
	one := apiCoverageDecision("one")
	two := apiCoverageDecision("two")
	two.Status = contracts.DecisionStatusResolved
	if err := store.Create(&one); err != nil {
		t.Fatalf("create one: %v", err)
	}
	if err := store.Create(&two); err != nil {
		t.Fatalf("create two: %v", err)
	}
	if err := store.Create(&one); err == nil {
		t.Fatal("expected duplicate create error")
	}
	if _, err := store.Get("missing"); err == nil {
		t.Fatal("expected missing get error")
	}
	filtered, err := store.List("ignored", contracts.DecisionStatusResolved)
	if err != nil {
		t.Fatalf("list filtered: %v", err)
	}
	if len(filtered) != 1 || filtered[0].RequestID != "two" {
		t.Fatalf("filtered decisions = %+v", filtered)
	}
	missing := apiCoverageDecision("missing")
	if err := store.Update(&missing); err == nil {
		t.Fatal("expected missing update error")
	}
	copyOne, err := store.Get("one")
	if err != nil {
		t.Fatalf("get one: %v", err)
	}
	copyOne.Title = "mutated copy"
	again, _ := store.Get("one")
	if again.Title == "mutated copy" {
		t.Fatal("Get should return a copy")
	}
}

type apiCoverageStateProvider struct {
	state *contracts.GlobalAutonomyState
	err   error
}

func (p apiCoverageStateProvider) ComputeState(_ string) (*contracts.GlobalAutonomyState, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.state, nil
}

func TestCoverageAutonomyHandlerBranches(t *testing.T) {
	handler := NewAutonomyHandler(apiCoverageStateProvider{state: &contracts.GlobalAutonomyState{OrgID: "org-1"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/autonomy/control", strings.NewReader(`{"action":"PAUSE"}`))
	handler.HandleControl(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported control status = %d, want 400", rec.Code)
	}

	handler = NewAutonomyHandler(NewInMemoryAutonomyProvider())
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/autonomy/control", strings.NewReader(`{`))
	handler.HandleControl(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid control JSON status = %d, want 400", rec.Code)
	}

	provider := NewInMemoryAutonomyProvider()
	provider.SetGlobalMode(contracts.GlobalModePaused)
	handler = NewAutonomyHandler(provider)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/autonomy/control", strings.NewReader(`{"action":"PAUSE"}`))
	handler.HandleControl(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("no-op pause status = %d, want 200", rec.Code)
	}

	failing := NewAutonomyHandler(apiCoverageStateProvider{err: errors.New("state failed")})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/autonomy/state", nil)
	failing.HandleGetState(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("state error status = %d, want 500", rec.Code)
	}

	provider = NewInMemoryAutonomyProvider()
	provider.AddRun(contracts.RunSummaryProjection{RunID: "active", Status: "active", NextAction: "verify deploy"})
	provider.AddRun(contracts.RunSummaryProjection{RunID: "pending", Status: "pending", NextAction: "start rollout"})
	for i := 0; i < 5; i++ {
		provider.AddDecisionRequest(apiCoverageDecision(fmt.Sprintf("blocker-%d", i)))
	}
	state, err := provider.ComputeState("org-risk")
	if err != nil {
		t.Fatalf("ComputeState: %v", err)
	}
	if state.Summary.Now != "verify deploy" || state.Summary.Next != "start rollout" {
		t.Fatalf("unexpected summary: %+v", state.Summary)
	}
	if state.RiskLevel != contracts.RiskLevelCritical {
		t.Fatalf("risk = %s, want CRITICAL", state.RiskLevel)
	}

	highProvider := NewInMemoryAutonomyProvider()
	for i := 0; i < 3; i++ {
		highProvider.AddRun(contracts.RunSummaryProjection{RunID: fmt.Sprintf("blocked-%d", i), CurrentStage: contracts.RunStageBlocked})
	}
	highState, err := highProvider.ComputeState("org-high")
	if err != nil {
		t.Fatalf("ComputeState high: %v", err)
	}
	if highState.RiskLevel != contracts.RiskLevelHigh {
		t.Fatalf("risk = %s, want HIGH", highState.RiskLevel)
	}
}

func TestCoverageLaunchpadHelperBranches(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/launchpad/plan", strings.NewReader(`{`))
	if _, ok := decodeLaunchpadPlanRequest(rec, req); ok || rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid launchpad request ok=%v status=%d", ok, rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/launchpad/plan", strings.NewReader(`{"app_id":"app","substrate_id":"sub"}`))
	decoded, ok := decodeLaunchpadPlanRequest(rec, req)
	if !ok || decoded.Principal != "console" {
		t.Fatalf("decoded launchpad request = %+v ok=%v", decoded, ok)
	}

	catalog := &launchregistry.Catalog{
		Root: ".",
		Apps: []launchregistry.AppSpec{{ID: "app", Name: "App"}},
	}
	plan, err := compileLaunchpadPlan(catalog, launchpadPlanRequest{AppID: "missing", SubstrateID: "sub", Principal: "operator"})
	if err == nil || plan.ReasonCode != "ERR_LAUNCHPAD_UNKNOWN_APP" {
		t.Fatalf("unknown app plan=%+v err=%v", plan, err)
	}
	plan, err = compileLaunchpadPlan(catalog, launchpadPlanRequest{AppID: "app", SubstrateID: "missing", Principal: "operator"})
	if err == nil || plan.ReasonCode != "ERR_LAUNCHPAD_UNKNOWN_SUBSTRATE" {
		t.Fatalf("unknown substrate plan=%+v err=%v", plan, err)
	}
	if coalesce("left", "right") != "left" || coalesce("", "right") != "right" {
		t.Fatal("coalesce returned unexpected value")
	}

	server := &Server{}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/launchpad/plan", strings.NewReader(`{"app_id":"missing","substrate_id":"sub","principal":"operator"}`))
	server.handleLaunchpadPlan(rec, req, catalog)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("handleLaunchpadPlan status = %d, want 202", rec.Code)
	}

	t.Setenv("HELM_LAUNCHPAD_HOME", t.TempDir())
	for name, tc := range map[string]struct {
		method string
		rest   string
		want   int
	}{
		"missing launch id": {method: http.MethodGet, rest: "", want: http.StatusBadRequest},
		"missing run":       {method: http.MethodGet, rest: "missing", want: http.StatusNotFound},
		"bad operation":     {method: http.MethodPost, rest: "missing/unknown", want: http.StatusMethodNotAllowed},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, "/api/v1/launchpad/launches/"+tc.rest, nil)
			server.handleLaunchpadRunPath(rec, req, tc.rest)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestCoverageMemoryIdempotencyStoreBranches(t *testing.T) {
	store := NewIdempotencyStore(time.Minute)
	store.entries["hit"] = &cachedResponse{StatusCode: http.StatusAccepted, Body: []byte("cached"), CachedAt: time.Now()}
	if cached, hit := store.Acquire("hit"); !hit || cached == nil || cached.StatusCode != http.StatusAccepted {
		t.Fatalf("expected acquire cache hit, got hit=%v cached=%+v", hit, cached)
	}

	store.entries["expired"] = &cachedResponse{StatusCode: http.StatusOK, CachedAt: time.Now().Add(-time.Hour)}
	if cached, hit := store.Acquire("expired"); hit || cached != nil {
		t.Fatalf("expired acquire should miss, got hit=%v cached=%+v", hit, cached)
	}
	store.Release("expired")
	if cached, hit := store.Check("expired"); hit || cached != nil {
		t.Fatalf("expired check should miss, got hit=%v cached=%+v", hit, cached)
	}

	raceStore := &MemoryIdempotencyStore{
		entries:  make(map[string]*cachedResponse),
		inflight: make(map[string]chan struct{}),
		ttl:      time.Minute,
	}
	if cached, hit := raceStore.Acquire("race"); hit || cached != nil {
		t.Fatalf("first acquire should win race, got hit=%v cached=%+v", hit, cached)
	}
	done := make(chan *cachedResponse, 1)
	go func() {
		cached, hit := raceStore.Acquire("race")
		if !hit {
			done <- nil
			return
		}
		done <- cached
	}()
	time.Sleep(10 * time.Millisecond)
	if err := raceStore.Set("race", "request-hash", http.StatusCreated, http.Header{"Content-Type": []string{"text/plain"}}, []byte("created")); err != nil {
		t.Fatalf("set race cache: %v", err)
	}
	raceStore.Release("race")
	select {
	case cached := <-done:
		if cached == nil || cached.StatusCode != http.StatusCreated {
			t.Fatalf("waiting acquire cached=%+v", cached)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting acquire did not unblock")
	}
}

func TestCoveragePostgresIdempotencyStore(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	store := NewPostgresIdempotencyStore(db, time.Minute)

	mock.ExpectQuery("SELECT request_hash, status_code, headers, body, cached_at FROM idempotency_keys").
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)
	if cached, ok := store.Check("missing"); ok || cached != nil {
		t.Fatalf("missing check got ok=%v cached=%+v", ok, cached)
	}

	mock.ExpectQuery("SELECT request_hash, status_code, headers, body, cached_at FROM idempotency_keys").
		WithArgs("hit").
		WillReturnRows(sqlmock.NewRows([]string{"request_hash", "status_code", "headers", "body", "cached_at"}).
			AddRow("request-hash", http.StatusOK, []byte("{}"), []byte(`{"ok":true}`), time.Now()))
	cached, ok := store.Check("hit")
	if !ok || cached == nil || cached.StatusCode != http.StatusOK || cached.Headers.Get("Content-Type") != "application/json" {
		t.Fatalf("hit check got ok=%v cached=%+v", ok, cached)
	}

	mock.ExpectQuery("SELECT request_hash, status_code, headers, body, cached_at FROM idempotency_keys").
		WithArgs("expired").
		WillReturnRows(sqlmock.NewRows([]string{"request_hash", "status_code", "headers", "body", "cached_at"}).
			AddRow("request-hash", http.StatusOK, []byte("{}"), []byte(`{}`), time.Now().Add(-time.Hour)))
	mock.ExpectExec("DELETE FROM idempotency_keys WHERE key = ").
		WithArgs("expired").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if cached, ok := store.Check("expired"); ok || cached != nil {
		t.Fatalf("expired check got ok=%v cached=%+v", ok, cached)
	}

	plainHeaders, err := json.Marshal(http.Header{"Content-Type": []string{"text/plain"}})
	if err != nil {
		t.Fatal(err)
	}
	emptyHeaders, err := json.Marshal(http.Header(nil))
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec("INSERT INTO idempotency_keys").
		WithArgs("set-key", "request-hash", http.StatusCreated, plainHeaders, []byte("body")).
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.Set("set-key", "request-hash", http.StatusCreated, http.Header{"Content-Type": []string{"text/plain"}}, []byte("body")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	mock.ExpectExec("INSERT INTO idempotency_keys").
		WithArgs("set-error", "request-hash", http.StatusOK, emptyHeaders, []byte("body")).
		WillReturnError(errors.New("insert failed"))
	if err := store.Set("set-error", "request-hash", http.StatusOK, nil, []byte("body")); err == nil {
		t.Fatal("expected Set error")
	}

	mock.ExpectExec("DELETE FROM idempotency_keys WHERE cached_at <").
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	store.Cleanup()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestCoverageMemoryHTTPHandlers(t *testing.T) {
	service := NewMemoryService()
	for name, tc := range map[string]struct {
		handler func(http.ResponseWriter, *http.Request)
		method  string
		body    string
		want    int
	}{
		"ingest method": {
			handler: service.HandleIngest,
			method:  http.MethodGet,
			want:    http.StatusMethodNotAllowed,
		},
		"ingest invalid json": {
			handler: service.HandleIngest,
			method:  http.MethodPost,
			body:    `{`,
			want:    http.StatusBadRequest,
		},
		"ingest missing fields": {
			handler: service.HandleIngest,
			method:  http.MethodPost,
			body:    `{"tenant_id":"tenant"}`,
			want:    http.StatusBadRequest,
		},
		"ingest service error": {
			handler: service.HandleIngest,
			method:  http.MethodPost,
			body:    `{"tenant_id":"tenant","source_id":"source","content":"content"}`,
			want:    http.StatusInternalServerError,
		},
		"search method": {
			handler: service.HandleSearch,
			method:  http.MethodGet,
			want:    http.StatusMethodNotAllowed,
		},
		"search invalid json": {
			handler: service.HandleSearch,
			method:  http.MethodPost,
			body:    `{`,
			want:    http.StatusBadRequest,
		},
		"search success": {
			handler: service.HandleSearch,
			method:  http.MethodPost,
			body:    `{"tenant_id":"tenant","query":"receipt","max_results":3}`,
			want:    http.StatusOK,
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, "/", strings.NewReader(tc.body))
			tc.handler(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestCoverageOpenAIProxyBranches(t *testing.T) {
	rec := httptest.NewRecorder()
	HandleOpenAIProxy(rec, httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status = %d, want 405", rec.Code)
	}

	rec = httptest.NewRecorder()
	HandleOpenAIProxy(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid body status = %d, want 400", rec.Code)
	}

	t.Setenv(upstreamURLEnv, "")
	t.Setenv(upstreamAPIKeyEnv, "")
	t.Setenv(runtimeAdminAPIKeyEnv, "helm-admin-secret")
	rec = httptest.NewRecorder()
	HandleOpenAIProxy(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"messages":[]}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing upstream status = %d, want 503", rec.Code)
	}

	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected upstream path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer provider-secret" {
			t.Fatalf("upstream authorization = %q, want server-owned provider credential", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-test"}`))
	}))
	defer upstream.Close()
	t.Setenv(upstreamURLEnv, upstream.URL)
	t.Setenv(upstreamAPIKeyEnv, "")
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer helm-admin-secret")
	HandleOpenAIProxy(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing upstream credential status = %d, want 503", rec.Code)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0 when the provider credential is absent", got)
	}

	t.Setenv(upstreamAPIKeyEnv, "helm-admin-secret")
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer helm-admin-secret")
	HandleOpenAIProxy(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("shared runtime and provider credential status = %d, want 503", rec.Code)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0 when credentials are shared", got)
	}

	t.Setenv(upstreamAPIKeyEnv, "provider-secret")
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer helm-admin-secret")
	HandleOpenAIProxy(rec, req)
	if rec.Code != http.StatusTeapot || rec.Header().Get("X-HELM-Governed") != "true" || rec.Header().Get("X-HELM-Model") != "gpt-4" {
		t.Fatalf("upstream proxy status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 after a configured request", got)
	}

	failed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	failedURL := failed.URL
	failed.Close()
	t.Setenv(upstreamURLEnv, failedURL)
	rec = httptest.NewRecorder()
	HandleOpenAIProxy(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-test","messages":[]}`)))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("failed upstream status = %d, want 502", rec.Code)
	}
}

func TestOpenAICompletionsURL(t *testing.T) {
	for name, tc := range map[string]struct {
		upstream string
		want     string
	}{
		"base URL": {
			upstream: "https://api.example.test",
			want:     "https://api.example.test/v1/chat/completions",
		},
		"base URL trailing slash": {
			upstream: "https://api.example.test/",
			want:     "https://api.example.test/v1/chat/completions",
		},
		"versioned URL": {
			upstream: "https://api.example.test/v1",
			want:     "https://api.example.test/v1/chat/completions",
		},
		"versioned URL trailing slash": {
			upstream: "https://api.example.test/v1/",
			want:     "https://api.example.test/v1/chat/completions",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := openAICompletionsURL(tc.upstream); got != tc.want {
				t.Fatalf("openAICompletionsURL(%q) = %q, want %q", tc.upstream, got, tc.want)
			}
		})
	}
}

func TestCredentialsEqual(t *testing.T) {
	if credentialsEqual("", "") {
		t.Fatal("empty credentials must not compare as configured credentials")
	}
	if credentialsEqual("provider-secret", "helm-admin-secret") {
		t.Fatal("different credentials compared equal")
	}
	if !credentialsEqual("shared-secret", "shared-secret") {
		t.Fatal("identical credentials did not compare equal")
	}
}

func TestCoverageTrustKeyHandlerBranches(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	handler := &TrustKeyHandler{Registry: trustregistry.NewTrustRegistry()}

	for name, tc := range map[string]struct {
		method string
		body   string
		want   int
		add    bool
	}{
		"add method":      {method: http.MethodGet, want: http.StatusMethodNotAllowed, add: true},
		"add bad json":    {method: http.MethodPost, body: `{`, want: http.StatusBadRequest, add: true},
		"add missing":     {method: http.MethodPost, body: `{"tenant_id":"tenant"}`, want: http.StatusBadRequest, add: true},
		"add bad key":     {method: http.MethodPost, body: `{"tenant_id":"tenant","key_id":"key","public_key":"abc"}`, want: http.StatusBadRequest, add: true},
		"revoke method":   {method: http.MethodGet, want: http.StatusMethodNotAllowed},
		"revoke bad json": {method: http.MethodPost, body: `{`, want: http.StatusBadRequest},
		"revoke missing":  {method: http.MethodPost, body: `{"tenant_id":"tenant"}`, want: http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, "/", strings.NewReader(tc.body))
			if tc.add {
				handler.HandleAddKey(rec, req)
			} else {
				handler.HandleRevokeKey(rec, req)
			}
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	rec := httptest.NewRecorder()
	addBody := fmt.Sprintf(`{"tenant_id":"tenant","key_id":"key","public_key":"%s"}`, pubHex)
	handler.HandleAddKey(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(addBody)))
	if rec.Code != http.StatusOK || !handler.Registry.IsAuthorized("tenant", "key") {
		t.Fatalf("add key status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handler.HandleRevokeKey(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"tenant_id":"tenant","key_id":"key"}`)))
	if rec.Code != http.StatusOK || handler.Registry.IsAuthorized("tenant", "key") {
		t.Fatalf("revoke key status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func marshalAPIValue(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(data)
}
