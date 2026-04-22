package compliance

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestAPI() (*APIHandler, *http.ServeMux) {
	scorer := NewComplianceScorer()
	fixedClock := func() time.Time {
		return time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	}
	scorer.WithClock(fixedClock)

	scorer.InitFramework("hipaa", 89)
	scorer.InitFramework("gdpr", 50)

	handler := NewAPIHandler(scorer).WithAPIClock(fixedClock)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	return handler, mux
}

func TestStatusEndpoint_AllFrameworks(t *testing.T) {
	_, mux := newTestAPI()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp StatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(resp.Frameworks) != 2 {
		t.Errorf("expected 2 frameworks, got %d", len(resp.Frameworks))
	}
	if !resp.OverallCompliant {
		t.Error("expected overall compliant with no violations")
	}
	if resp.ResponseHash == "" {
		t.Error("expected non-empty response hash")
	}
}

func TestStatusEndpoint_SingleFramework(t *testing.T) {
	_, mux := newTestAPI()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/status?framework=hipaa", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp StatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(resp.Frameworks) != 1 {
		t.Errorf("expected 1 framework, got %d", len(resp.Frameworks))
	}
	if _, ok := resp.Frameworks["hipaa"]; !ok {
		t.Error("expected hipaa in response")
	}
}

func TestStatusEndpoint_UnknownFramework(t *testing.T) {
	_, mux := newTestAPI()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/status?framework=unknown", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestStatusEndpoint_MethodNotAllowed(t *testing.T) {
	_, mux := newTestAPI()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestHealthEndpoint_Healthy(t *testing.T) {
	_, mux := newTestAPI()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("expected healthy, got %s", resp.Status)
	}
	if resp.FrameworkCount != 2 {
		t.Errorf("expected 2 frameworks, got %d", resp.FrameworkCount)
	}
}

func TestHealthEndpoint_Degraded(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("hipaa", 10)
	// Record many violations to drop score below 70.
	for i := 0; i < 8; i++ {
		scorer.RecordEvent(ComplianceEvent{
			Framework: "hipaa",
			ControlID: "ctrl-" + string(rune('a'+i)),
			Passed:    false,
		})
	}

	handler := NewAPIHandler(scorer)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp HealthResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Status != "degraded" && resp.Status != "critical" {
		t.Errorf("expected degraded or critical, got %s (score=%d)", resp.Status, resp.LowestScore)
	}
}

func TestHealthEndpoint_NoFrameworks(t *testing.T) {
	scorer := NewComplianceScorer()
	handler := NewAPIHandler(scorer)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp HealthResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Status != "healthy" {
		t.Errorf("expected healthy for empty scorer, got %s", resp.Status)
	}
}

func TestRecordEventEndpoint(t *testing.T) {
	_, mux := newTestAPI()

	body, _ := json.Marshal(EventRequest{
		Framework: "hipaa",
		ControlID: "ctrl-001",
		Passed:    true,
		Reason:    "audit check passed",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/event", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp EventResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !resp.Accepted {
		t.Error("expected accepted=true")
	}
	if resp.Score == nil {
		t.Fatal("expected score in response")
	}
	if resp.Score.Framework != "hipaa" {
		t.Errorf("expected hipaa, got %s", resp.Score.Framework)
	}
}

func TestRecordEventEndpoint_MissingFramework(t *testing.T) {
	_, mux := newTestAPI()

	body, _ := json.Marshal(EventRequest{
		ControlID: "ctrl-001",
		Passed:    true,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/event", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestRecordEventEndpoint_MissingControlID(t *testing.T) {
	_, mux := newTestAPI()

	body, _ := json.Marshal(EventRequest{
		Framework: "hipaa",
		Passed:    true,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/event", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestRecordEventEndpoint_WrongContentType(t *testing.T) {
	_, mux := newTestAPI()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/event", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", rec.Code)
	}
}

func TestRecordEventEndpoint_InvalidJSON(t *testing.T) {
	_, mux := newTestAPI()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/event", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestRecordEventEndpoint_WrongMethod(t *testing.T) {
	_, mux := newTestAPI()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/event", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestRecordEventEndpoint_ViolationUpdatesScore(t *testing.T) {
	_, mux := newTestAPI()

	// Record a violation.
	body, _ := json.Marshal(EventRequest{
		Framework: "hipaa",
		ControlID: "ctrl-fail",
		Passed:    false,
		Reason:    "PHI exposed",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/event", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp EventResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Score.ViolationCount != 1 {
		t.Errorf("expected 1 violation, got %d", resp.Score.ViolationCount)
	}
	if resp.Score.Score >= 100 {
		t.Error("expected score to decrease after violation")
	}
}

func TestResponseHash_Deterministic(t *testing.T) {
	_, mux := newTestAPI()

	// Make same request twice.
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/status", nil)
	rec1 := httptest.NewRecorder()
	mux.ServeHTTP(rec1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/status", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp1, resp2 StatusResponse
	_ = json.NewDecoder(rec1.Body).Decode(&resp1)
	_ = json.NewDecoder(rec2.Body).Decode(&resp2)

	// Same scorer state + same clock = same hash.
	if resp1.ResponseHash != resp2.ResponseHash {
		t.Errorf("expected deterministic hash, got %s vs %s", resp1.ResponseHash, resp2.ResponseHash)
	}
}

func TestContentTypeIsJSON(t *testing.T) {
	_, mux := newTestAPI()

	endpoints := []string{
		"/api/v1/compliance/status",
		"/api/v1/compliance/health",
	}

	for _, endpoint := range endpoints {
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		ct := rec.Header().Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("%s: expected application/json, got %s", endpoint, ct)
		}
	}
}
