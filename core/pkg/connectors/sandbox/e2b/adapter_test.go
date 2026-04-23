package e2b

import (
	"encoding/json"
	"fmt"
	"io"
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

// ── Mock E2B Server ─────────────────────────────────────────────

type mockE2B struct {
	mu        sync.Mutex
	sandboxes map[string]*mockSBX
	nextID    int
}

type mockSBX struct {
	ID     string
	Status string
	Files  map[string][]byte
}

func newMockServer() (*httptest.Server, *mockE2B) {
	mock := &mockE2B{sandboxes: make(map[string]*mockSBX)}
	mux := http.NewServeMux()

	// Create.
	mux.HandleFunc("POST /sandboxes", func(w http.ResponseWriter, r *http.Request) {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		mock.nextID++
		id := fmt.Sprintf("e2b-%d", mock.nextID)
		mock.sandboxes[id] = &mockSBX{ID: id, Status: "running", Files: make(map[string][]byte)}
		json.NewEncoder(w).Encode(map[string]string{"sandboxID": id})
	})

	// Delete.
	mux.HandleFunc("DELETE /sandboxes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		mock.mu.Lock()
		defer mock.mu.Unlock()
		if sbx, ok := mock.sandboxes[id]; ok {
			sbx.Status = "terminated"
		}
		w.WriteHeader(200)
	})

	// Pause.
	mux.HandleFunc("POST /sandboxes/{id}/pause", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		mock.mu.Lock()
		defer mock.mu.Unlock()
		if sbx, ok := mock.sandboxes[id]; ok {
			sbx.Status = "paused"
		}
		w.WriteHeader(200)
	})

	// Resume.
	mux.HandleFunc("POST /sandboxes/{id}/resume", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		mock.mu.Lock()
		defer mock.mu.Unlock()
		if sbx, ok := mock.sandboxes[id]; ok {
			sbx.Status = "running"
		}
		json.NewEncoder(w).Encode(map[string]string{"sandboxID": id})
	})

	// Exec.
	mux.HandleFunc("POST /sandboxes/{id}/process", func(w http.ResponseWriter, r *http.Request) {
		var req e2bExecReq
		json.NewDecoder(r.Body).Decode(&req)

		stdout := ""
		timedOut := ""
		// Simulate echo.
		if len(req.Cmd) > 5 && req.Cmd[:5] == "echo " {
			stdout = req.Cmd[5:] + "\n"
		}
		// Simulate timeout.
		if len(req.Cmd) > 6 && req.Cmd[:6] == "sleep " && req.Timeout > 0 {
			timedOut = "timeout"
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"stdout":     stdout,
			"stderr":     "",
			"exitCode":   0,
			"error":      timedOut,
			"durationMs": 1,
		})
	})

	// ReadFile.
	mux.HandleFunc("GET /sandboxes/{id}/filesystem", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("PUT /sandboxes/{id}/filesystem", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		path := r.URL.Query().Get("path")
		mock.mu.Lock()
		sbx, ok := mock.sandboxes[id]
		mock.mu.Unlock()
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		data, _ := io.ReadAll(r.Body)
		mock.mu.Lock()
		sbx.Files[path] = data
		mock.mu.Unlock()
		w.WriteHeader(201)
	})

	// Logs.
	mux.HandleFunc("GET /sandboxes/{id}/logs", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"logs": []interface{}{}})
	})

	// ListFiles.
	mux.HandleFunc("GET /sandboxes/{id}/filesystem/list", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"entries": []interface{}{}})
	})

	server := httptest.NewServer(mux)
	return server, mock
}

func newTestAdapter(server *httptest.Server) *Adapter {
	cfg := Config{
		APIURL:         server.URL,
		APIKey:         "test-key-123",
		TemplateID:     "default",
		DefaultTimeout: 5 * time.Minute,
	}
	return New(cfg).WithHTTPClient(server.Client())
}

// ── Tests ───────────────────────────────────────────────────────

func TestE2B_ConformanceSuite(t *testing.T) {
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

func TestE2B_PreflightDeniesNoAPIKey(t *testing.T) {
	cfg := Config{
		APIURL:         "https://api.e2b.dev",
		APIKey:         "",
		DefaultTimeout: 5 * time.Minute,
	}
	adapter := New(cfg)

	report, err := adapter.Preflight(t.Context())
	require.NoError(t, err)
	assert.False(t, report.StrictPassed, "preflight must fail without API key")
}

func TestE2B_PreflightPasses(t *testing.T) {
	cfg := Config{
		APIURL:         "https://api.e2b.dev",
		APIKey:         "key-123",
		DefaultTimeout: 5 * time.Minute,
	}
	adapter := New(cfg)

	report, err := adapter.Preflight(t.Context())
	require.NoError(t, err)
	assert.True(t, report.StrictPassed, "preflight must pass with valid config")
}

func TestE2B_PauseResumeSupported(t *testing.T) {
	server, _ := newMockServer()
	defer server.Close()
	adapter := newTestAdapter(server)

	ctx := t.Context()
	handle, err := adapter.Create(ctx, &actuators.SandboxSpec{
		Runtime:   "default",
		Resources: actuators.ResourceSpec{MemoryMB: 256, Timeout: 30 * time.Second},
	})
	require.NoError(t, err)

	require.NoError(t, adapter.Pause(ctx, handle.ID))
	resumed, err := adapter.Resume(ctx, handle.ID)
	require.NoError(t, err)
	assert.Equal(t, actuators.StatusRunning, resumed.Status)

	require.NoError(t, adapter.Terminate(ctx, handle.ID))
}
