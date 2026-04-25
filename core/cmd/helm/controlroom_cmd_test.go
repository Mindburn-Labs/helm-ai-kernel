package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestControlRoomReceiptsReadsJSONL(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "receipts.jsonl"), []byte(`{"receipt_id":"r1"}`+"\n"+`{"receipt_id":"r2"}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	mux := newControlRoomMux(controlRoomConfig{ReceiptsDir: dir})
	req := httptest.NewRequest(http.MethodGet, "/api/receipts", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Receipts []map[string]any `json:"receipts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Receipts) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(body.Receipts))
	}
}

func TestControlRoomProofGraphReadsNodesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nodes.json")
	if err := os.WriteFile(path, []byte(`{"nodes":[{"id":"n1"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	mux := newControlRoomMux(controlRoomConfig{ProofGraphFile: path})
	req := httptest.NewRequest(http.MethodGet, "/api/proofgraph", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Nodes []map[string]any `json:"nodes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Nodes) != 1 || body.Nodes[0]["id"] != "n1" {
		t.Fatalf("unexpected nodes: %+v", body.Nodes)
	}
}
