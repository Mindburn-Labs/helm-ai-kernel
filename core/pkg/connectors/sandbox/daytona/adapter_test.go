package daytona

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

// ── Mock Daytona Server ─────────────────────────────────────────

type mockDaytona struct {
	mu        sync.Mutex
	sandboxes map[string]*mockSBX
	nextID    int
}

type mockSBX struct {
	ID     string
	Status string
	Files  map[string][]byte
}

func newMockServer() (*httptest.Server, *mockDaytona) {
	mock := &mockDaytona{sandboxes: make(map[string]*mockSBX)}
	mux := http.NewServeMux()

	// Create.
	mux.HandleFunc("POST /sandbox", func(w http.ResponseWriter, _ *http.Request) {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		mock.nextID++
		id := fmt.Sprintf("dtn-%d", mock.nextID)
		mock.sandboxes[id] = &mockSBX{ID: id, Status: "running", Files: make(map[string][]byte)}
		json.NewEncoder(w).Encode(map[string]string{"sandboxId": id})
	})

	// Delete.
	mux.HandleFunc("DELETE /sandbox/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		mock.mu.Lock()
		defer mock.mu.Unlock()
		if sbx, ok := mock.sandboxes[id]; ok {
			sbx.Status = "terminated"
		}
		w.WriteHeader(200)
	})

	// Exec.
	mux.HandleFunc("POST /sandbox/{id}/process/execute", func(w http.ResponseWriter, r *http.Request) {
		var req daytonaExecReq
		json.NewDecoder(r.Body).Decode(&req)

		output := ""
		timedOut := false

		// Simulate echo.
		if len(req.Command) > 5 && req.Command[:5] == "echo " {
			output = req.Command[5:] + "\n"
		}
		// Simulate timeout.
		if len(req.Command) > 6 && req.Command[:6] == "sleep " && req.Timeout > 0 {
			timedOut = true
		}

		json.NewEncoder(w).Encode(daytonaExecResp{
			Output:     output,
			ExitCode:   0,
			TimedOut:   timedOut,
			DurationMs: 1,
		})
	})

	// ReadFile.
	mux.HandleFunc("GET /sandbox/{id}/filesystem", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("PUT /sandbox/{id}/filesystem", func(w http.ResponseWriter, r *http.Request) {
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

	// ListFiles.
	mux.HandleFunc("GET /sandbox/{id}/filesystem/list", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"entries": []interface{}{}})
	})

	// Logs.
	mux.HandleFunc("GET /sandbox/{id}/logs", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"logs": []interface{}{}})
	})

	server := httptest.NewServer(mux)
	return server, mock
}

func newTestAdapter(server *httptest.Server) *Adapter {
	cfg := Config{
		BaseURL:            server.URL,
		APIKey:             "test-key-123",
		WorkspaceIsolation: true,
		DefaultLanguage:    "bash",
	}
	return New(cfg).WithHTTPClient(server.Client())
}

// ── Tests ───────────────────────────────────────────────────────

func TestDaytona_ConformanceSuite(t *testing.T) {
	server, _ := newMockServer()
	defer server.Close()

	adapter := newTestAdapter(server)
	suite := conformance.NewSuite()
	sbxconformance.RegisterSandboxTests(suite, adapter)

	// Run L2 — Daytona Pause/Resume returns ErrNotSupported which the
	// conformance suite handles as a skip.
	results := suite.Run(conformance.LevelL2)
	for _, r := range results {
		t.Run(r.Name, func(t *testing.T) {
			if !r.Passed {
				t.Errorf("FAIL: %s — %s", r.TestID, r.Error)
			}
		})
	}
}

func TestDaytona_PauseResumeNotSupported(t *testing.T) {
	server, _ := newMockServer()
	defer server.Close()
	adapter := newTestAdapter(server)

	ctx := t.Context()
	handle, err := adapter.Create(ctx, &actuators.SandboxSpec{
		Runtime:   "default",
		Resources: actuators.ResourceSpec{MemoryMB: 256, Timeout: 30 * time.Second},
	})
	require.NoError(t, err)

	err = adapter.Pause(ctx, handle.ID)
	assert.ErrorIs(t, err, actuators.ErrNotSupported)

	_, err = adapter.Resume(ctx, handle.ID)
	assert.ErrorIs(t, err, actuators.ErrNotSupported)

	require.NoError(t, adapter.Terminate(ctx, handle.ID))
}

func TestDaytona_PreflightDeniesNoAPIKey(t *testing.T) {
	adapter := New(Config{
		BaseURL:            "https://api.daytona.io",
		APIKey:             "",
		WorkspaceIsolation: true,
	})

	report, err := adapter.Preflight(t.Context())
	require.NoError(t, err)
	assert.False(t, report.StrictPassed)
}

func TestDaytona_PreflightDeniesNoIsolation(t *testing.T) {
	adapter := New(Config{
		BaseURL:            "https://api.daytona.io",
		APIKey:             "key-123",
		WorkspaceIsolation: false,
	})

	report, err := adapter.Preflight(t.Context())
	require.NoError(t, err)
	assert.False(t, report.StrictPassed, "preflight must fail without workspace isolation")
}

func TestDaytona_PreflightPasses(t *testing.T) {
	adapter := New(Config{
		BaseURL:            "https://api.daytona.io",
		APIKey:             "key-123",
		WorkspaceIsolation: true,
	})

	report, err := adapter.Preflight(t.Context())
	require.NoError(t, err)
	assert.True(t, report.StrictPassed)
}
