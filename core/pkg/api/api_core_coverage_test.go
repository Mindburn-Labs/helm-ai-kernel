package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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

	t.Setenv("HELM_UPSTREAM_URL", "")
	rec = httptest.NewRecorder()
	HandleOpenAIProxy(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"messages":[]}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing upstream status = %d, want 503", rec.Code)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected upstream path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization not forwarded: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-test"}`))
	}))
	defer upstream.Close()
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL)
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer token")
	HandleOpenAIProxy(rec, req)
	if rec.Code != http.StatusTeapot || rec.Header().Get("X-HELM-Governed") != "true" || rec.Header().Get("X-HELM-Model") != "gpt-6-sol" {
		t.Fatalf("upstream proxy status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}

	failed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	failedURL := failed.URL
	failed.Close()
	t.Setenv("HELM_UPSTREAM_URL", failedURL)
	rec = httptest.NewRecorder()
	HandleOpenAIProxy(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-test","messages":[]}`)))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("failed upstream status = %d, want 502", rec.Code)
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
