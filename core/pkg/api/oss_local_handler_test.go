package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestOSSLocalSummaryFromRunReport(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	evidenceDir := filepath.Join(root, "data", "evidence")
	receiptsDir := filepath.Join(root, "helm-receipts")
	if err := os.MkdirAll(evidenceDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(receiptsDir, 0o750); err != nil {
		t.Fatal(err)
	}

	report := map[string]any{
		"version":        "0.2.0",
		"schema_version": "1",
		"generated_at":   "2026-03-20T10:00:00Z",
		"template":       "starter",
		"provider":       "mock",
		"summary": map[string]any{
			"total":             2,
			"lamport_final":     2,
			"root_hash":         "sha256:root",
			"chain_verified":    true,
			"lamport_monotonic": true,
			"deny_path_tested":  true,
			"is_demo":           true,
		},
		"receipts": []map[string]any{
			{
				"receipt_id":    "rec-1",
				"timestamp":     "2026-03-20T10:00:00Z",
				"principal":     "planner",
				"action":        "PLAN",
				"verdict":       "ALLOW",
				"reason_code":   "ALLOW",
				"hash":          "hash-1",
				"lamport_clock": 1,
				"prev_hash":     "",
			},
			{
				"receipt_id":    "rec-2",
				"timestamp":     "2026-03-20T10:01:00Z",
				"principal":     "auditor",
				"action":        "DELETE",
				"verdict":       "DENY",
				"reason_code":   "DENY_POLICY_VIOLATION",
				"hash":          "hash-2",
				"lamport_clock": 2,
				"prev_hash":     "hash-1",
			},
		},
	}
	reportBytes, _ := json.Marshal(report)
	if err := os.WriteFile(filepath.Join(evidenceDir, "run-report.json"), reportBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	proofgraph := map[string]any{
		"nodes": []map[string]any{
			{"id": "n1"},
			{"id": "n2"},
		},
	}
	proofgraphBytes, _ := json.Marshal(proofgraph)
	if err := os.WriteFile(filepath.Join(receiptsDir, "proofgraph.json"), proofgraphBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	handler := NewOSSLocalHandler(OSSLocalConfig{
		EvidenceDir: evidenceDir,
		ReceiptsDir: receiptsDir,
		Version:     "v-test",
	})
	mux := http.NewServeMux()
	handler.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oss-local/summary", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("summary status = %d, want 200", rec.Code)
	}

	var resp OSSLocalSummaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if !resp.Connected {
		t.Fatal("expected connected summary")
	}
	if resp.Stats.ReceiptCount != 2 {
		t.Fatalf("receipt_count = %d, want 2", resp.Stats.ReceiptCount)
	}
	if resp.Stats.DenyCount != 1 {
		t.Fatalf("deny_count = %d, want 1", resp.Stats.DenyCount)
	}
	if resp.Stats.ProofgraphNodes != 2 {
		t.Fatalf("proofgraph_nodes = %d, want 2", resp.Stats.ProofgraphNodes)
	}
	if resp.LatestReport == nil || resp.LatestReport.Summary.RootHash != "sha256:root" {
		t.Fatalf("unexpected latest report: %#v", resp.LatestReport)
	}
}

func TestOSSLocalTimelineAndCapabilities(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	receiptsDir := filepath.Join(root, "helm-receipts")
	if err := os.MkdirAll(receiptsDir, 0o750); err != nil {
		t.Fatal(err)
	}

	jsonl := `{"receipt_id":"rec-a","timestamp":"2026-03-20T10:00:00Z","model":"gpt-5","status":"APPROVED","reason_code":"ALLOW","output_hash":"out-a","lamport_clock":1,"prev_hash":""}
{"receipt_id":"rec-b","timestamp":"2026-03-20T10:01:00Z","model":"gpt-5","status":"DENY","reason_code":"DENY_POLICY_VIOLATION","output_hash":"out-b","lamport_clock":2,"prev_hash":"out-a"}
`
	if err := os.WriteFile(filepath.Join(receiptsDir, "receipts-2026-03-20.jsonl"), []byte(jsonl), 0o644); err != nil {
		t.Fatal(err)
	}

	handler := NewOSSLocalHandler(OSSLocalConfig{
		EvidenceDir: filepath.Join(root, "data", "evidence"),
		ReceiptsDir: receiptsDir,
		Version:     "v-test",
	})
	mux := http.NewServeMux()
	handler.Register(mux)

	timelineReq := httptest.NewRequest(http.MethodGet, "/api/v1/oss-local/decision-timeline?limit=1", nil)
	timelineRec := httptest.NewRecorder()
	mux.ServeHTTP(timelineRec, timelineReq)
	if timelineRec.Code != http.StatusOK {
		t.Fatalf("timeline status = %d, want 200", timelineRec.Code)
	}

	var timeline OSSLocalTimelineResponse
	if err := json.NewDecoder(timelineRec.Body).Decode(&timeline); err != nil {
		t.Fatal(err)
	}
	if len(timeline.Decisions) != 1 {
		t.Fatalf("timeline decisions = %d, want 1", len(timeline.Decisions))
	}
	if timeline.Source != "proxy-jsonl" {
		t.Fatalf("timeline source = %q, want proxy-jsonl", timeline.Source)
	}

	capReq := httptest.NewRequest(http.MethodGet, "/api/v1/oss-local/capabilities", nil)
	capRec := httptest.NewRecorder()
	mux.ServeHTTP(capRec, capReq)
	if capRec.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d, want 200", capRec.Code)
	}

	var capabilities OSSLocalCapabilitiesResponse
	if err := json.NewDecoder(capRec.Body).Decode(&capabilities); err != nil {
		t.Fatal(err)
	}
	if capabilities.MCP.AuthModes["oauth"] {
		t.Fatal("oauth should be reported as unsupported in OSS local capabilities")
	}
	if !capabilities.ReadOnly {
		t.Fatal("capabilities should be read-only")
	}
}
