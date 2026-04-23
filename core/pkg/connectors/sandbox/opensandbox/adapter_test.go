package opensandbox

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conformance"
	sbxconformance "github.com/Mindburn-Labs/helm-oss/core/pkg/conformance/sandbox"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Mock OpenSandbox Server ─────────────────────────────────────

// mockOpenSandbox simulates the OpenSandbox REST API for testing.
type mockOpenSandbox struct {
	mu        sync.Mutex
	sandboxes map[string]*mockSBX
	nextID    int
}

type mockSBX struct {
	ID     string
	Status string
	Files  map[string][]byte
	Logs   []logEntry
}

type logEntry struct {
	Timestamp string `json:"timestamp"`
	Stream    string `json:"stream"`
	Line      string `json:"line"`
}

func newMockServer() (*httptest.Server, *mockOpenSandbox) {
	mock := &mockOpenSandbox{
		sandboxes: make(map[string]*mockSBX),
	}

	mux := http.NewServeMux()

	// Create sandbox.
	mux.HandleFunc("POST /api/sandbox", func(w http.ResponseWriter, r *http.Request) {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		mock.nextID++
		id := fmt.Sprintf("osb-%d", mock.nextID)
		mock.sandboxes[id] = &mockSBX{
			ID:     id,
			Status: "running",
			Files:  make(map[string][]byte),
		}
		json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "running"})
	})

	// Delete sandbox.
	mux.HandleFunc("DELETE /api/sandbox/", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/api/sandbox/"):]
		mock.mu.Lock()
		defer mock.mu.Unlock()
		if _, ok := mock.sandboxes[id]; !ok {
			http.Error(w, "not found", 404)
			return
		}
		mock.sandboxes[id].Status = "terminated"
		w.WriteHeader(200)
	})

	// Exec.
	mux.HandleFunc("POST /api/sandbox/{id}/exec", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		mock.mu.Lock()
		sbx, ok := mock.sandboxes[id]
		mock.mu.Unlock()
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		_ = sbx

		var req execRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Simulate: echo commands produce output.
		stdout := ""
		if len(req.Command) > 0 && req.Command[0] == "echo" {
			for i, arg := range req.Command[1:] {
				if i > 0 {
					stdout += " "
				}
				stdout += arg
			}
			stdout += "\n"
		}

		// Simulate timeout.
		timedOut := false
		if len(req.Command) > 0 && req.Command[0] == "sleep" && req.Timeout > 0 {
			timedOut = true
		}

		json.NewEncoder(w).Encode(execResponse{
			ExitCode:   0,
			Stdout:     stdout,
			DurationMs: 1,
			TimedOut:   timedOut,
		})
	})

	// Resume.
	mux.HandleFunc("POST /api/sandbox/{id}/resume", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		mock.mu.Lock()
		sbx, ok := mock.sandboxes[id]
		mock.mu.Unlock()
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		sbx.Status = "running"
		json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "running"})
	})

	// Pause.
	mux.HandleFunc("POST /api/sandbox/{id}/pause", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		mock.mu.Lock()
		sbx, ok := mock.sandboxes[id]
		mock.mu.Unlock()
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		sbx.Status = "paused"
		w.WriteHeader(200)
	})

	// ReadFile.
	mux.HandleFunc("GET /api/sandbox/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		path := r.URL.Query().Get("path")
		mock.mu.Lock()
		sbx, ok := mock.sandboxes[id]
		mock.mu.Unlock()
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		data, ok := sbx.Files[path]
		if !ok {
			http.Error(w, "file not found", 404)
			return
		}
		w.Write(data)
	})

	// WriteFile.
	mux.HandleFunc("PUT /api/sandbox/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		path := r.URL.Query().Get("path")
		mock.mu.Lock()
		sbx, ok := mock.sandboxes[id]
		mock.mu.Unlock()
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		data := make([]byte, r.ContentLength)
		r.Body.Read(data)
		sbx.Files[path] = data
		w.WriteHeader(201)
	})

	// ListFiles.
	mux.HandleFunc("GET /api/sandbox/{id}/files/list", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"entries": []interface{}{}})
	})

	// Network.
	mux.HandleFunc("PUT /api/sandbox/{id}/network", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})

	// Logs.
	mux.HandleFunc("GET /api/sandbox/{id}/logs", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"logs": []interface{}{}})
	})

	server := httptest.NewServer(mux)
	return server, mock
}

func newTestAdapter(server *httptest.Server) *Adapter {
	cfg := Config{
		BaseURL:          server.URL,
		APIKey:           "test-key-123",
		TLSRequired:      false, // httptest uses http://
		EgressStrictMode: true,
	}
	return New(cfg).WithHTTPClient(server.Client())
}

// ── Tests ───────────────────────────────────────────────────────

func TestOpenSandbox_ConformanceSuite(t *testing.T) {
	server, _ := newMockServer()
	defer server.Close()

	adapter := newTestAdapter(server)
	suite := conformance.NewSuite()
	sbxconformance.RegisterSandboxTests(suite, adapter)

	results := suite.Run(conformance.LevelL2)
	for _, r := range results {
		t.Run(r.Name, func(t *testing.T) {
			if !r.Passed {
				t.Errorf("FAIL: %s — %s", r.TestID, r.Error)
			}
		})
	}
}

func TestOpenSandbox_PreflightDeniesNoAPIKey(t *testing.T) {
	cfg := Config{
		BaseURL:          "https://example.com",
		APIKey:           "", // Missing!
		TLSRequired:      true,
		EgressStrictMode: true,
	}
	adapter := New(cfg)

	report, err := adapter.Preflight(t.Context())
	require.NoError(t, err)
	assert.False(t, report.StrictPassed, "preflight must fail without API key")

	// Verify that Create fails.
	_, err = adapter.Create(t.Context(), &actuators.SandboxSpec{
		Runtime:   "test",
		Resources: actuators.ResourceSpec{MemoryMB: 128, Timeout: 30 * time.Second},
	})
	assert.ErrorIs(t, err, actuators.ErrPreflightFailed)
}

func TestOpenSandbox_PreflightDeniesNoTLS(t *testing.T) {
	cfg := Config{
		BaseURL:          "http://insecure.example.com",
		APIKey:           "key-123",
		TLSRequired:      true,
		EgressStrictMode: true,
	}
	adapter := New(cfg)

	report, err := adapter.Preflight(t.Context())
	require.NoError(t, err)
	assert.False(t, report.StrictPassed, "preflight must fail without TLS")
}

func TestOpenSandbox_PreflightDeniesEgressDegraded(t *testing.T) {
	cfg := Config{
		BaseURL:          "https://example.com",
		APIKey:           "key-123",
		TLSRequired:      true,
		EgressStrictMode: false, // Degraded!
	}
	adapter := New(cfg)

	report, err := adapter.Preflight(t.Context())
	require.NoError(t, err)
	assert.False(t, report.StrictPassed, "preflight must fail with egress strict mode disabled")
}

func TestOpenSandbox_PreflightPasses(t *testing.T) {
	cfg := Config{
		BaseURL:          "https://secure.example.com",
		APIKey:           "key-123",
		TLSRequired:      true,
		EgressStrictMode: true,
	}
	adapter := New(cfg)

	report, err := adapter.Preflight(t.Context())
	require.NoError(t, err)
	assert.True(t, report.StrictPassed, "preflight must pass with valid config")
	assert.Len(t, report.Checks, 4)
}

func TestOpenSandbox_ExecReceiptDeterminism(t *testing.T) {
	server, _ := newMockServer()
	defer server.Close()
	adapter := newTestAdapter(server)

	ok, err := sbxconformance.VerifyReceiptDeterminism(adapter, &actuators.ExecRequest{
		Command: []string{"echo", "deterministic"},
	})
	require.NoError(t, err)
	assert.True(t, ok, "receipt hashes must be identical for identical commands")
}
