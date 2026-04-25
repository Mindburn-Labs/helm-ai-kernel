package main

import (
	"bufio"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/store"
)

//go:embed controlroom_assets
var controlRoomAssets embed.FS

type controlRoomConfig struct {
	ReceiptsDir    string
	ReceiptsDB     string
	ProofGraphFile string
}

func runControlRoom(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("control-room", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var port int
	var cfg controlRoomConfig
	cmd.IntVar(&port, "port", 8090, "Control-room UI port")
	cmd.StringVar(&cfg.ReceiptsDir, "receipts-dir", "./helm-receipts", "Directory with JSON or JSONL receipts")
	cmd.StringVar(&cfg.ReceiptsDB, "receipts-db", "", "SQLite receipt database")
	cmd.StringVar(&cfg.ProofGraphFile, "proofgraph-file", "", "ProofGraph JSON or JSONL file")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	mux := newControlRoomMux(cfg)
	addr := fmt.Sprintf(":%d", port)
	_, _ = fmt.Fprintf(stdout, "HELM Control Room\n")
	_, _ = fmt.Fprintf(stdout, "  UI:           http://localhost:%d\n", port)
	_, _ = fmt.Fprintf(stdout, "  Receipts dir: %s\n", cfg.ReceiptsDir)
	if cfg.ReceiptsDB != "" {
		_, _ = fmt.Fprintf(stdout, "  Receipts DB:  %s\n", cfg.ReceiptsDB)
	}
	if cfg.ProofGraphFile != "" {
		_, _ = fmt.Fprintf(stdout, "  ProofGraph:   %s\n", cfg.ProofGraphFile)
	}

	log.Printf("control-room listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	return 0
}

func newControlRoomMux(cfg controlRoomConfig) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(controlRoomAssets)))
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"status": "ok", "component": "control-room"})
	})
	mux.HandleFunc("/api/receipts", func(w http.ResponseWriter, r *http.Request) {
		receipts, err := loadControlRoomReceipts(r.Context(), cfg)
		if err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"receipts": receipts})
	})
	mux.HandleFunc("/api/proofgraph", func(w http.ResponseWriter, _ *http.Request) {
		nodes, err := loadControlRoomProofGraph(cfg)
		if err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"nodes": nodes})
	})
	mux.HandleFunc("/api/budget", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"configured": false, "daily_used": 0, "daily_limit": 0, "monthly_used": 0, "monthly_limit": 0})
	})
	return mux
}

func loadControlRoomReceipts(ctx context.Context, cfg controlRoomConfig) ([]any, error) {
	if cfg.ReceiptsDB != "" {
		db, err := sql.Open("sqlite", cfg.ReceiptsDB)
		if err != nil {
			return nil, err
		}
		defer func() { _ = db.Close() }()
		rs, err := store.NewSQLiteReceiptStore(db)
		if err != nil {
			return nil, err
		}
		receipts, err := rs.List(ctx, 500)
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, len(receipts))
		for _, receipt := range receipts {
			out = append(out, receipt)
		}
		return out, nil
	}
	return readJSONObjectsFromDir(cfg.ReceiptsDir)
}

func loadControlRoomProofGraph(cfg controlRoomConfig) ([]any, error) {
	candidates := []string{}
	if cfg.ProofGraphFile != "" {
		candidates = append(candidates, cfg.ProofGraphFile)
	}
	if cfg.ReceiptsDir != "" {
		candidates = append(candidates,
			filepath.Join(cfg.ReceiptsDir, "proofgraph.json"),
			filepath.Join(cfg.ReceiptsDir, "proofgraph.jsonl"),
			filepath.Join(cfg.ReceiptsDir, "proofgraph", "nodes.json"),
			filepath.Join(cfg.ReceiptsDir, "proofgraph", "nodes.jsonl"),
		)
	}
	for _, candidate := range candidates {
		nodes, err := readJSONObjectsFromFile(candidate)
		if err == nil {
			return nodes, nil
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return []any{}, nil
}

func readJSONObjectsFromDir(dir string) ([]any, error) {
	if dir == "" {
		return []any{}, nil
	}
	var out []any
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".json") && !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		items, readErr := readJSONObjectsFromFile(path)
		if readErr != nil {
			return readErr
		}
		out = append(out, items...)
		return nil
	})
	if os.IsNotExist(err) {
		return []any{}, nil
	}
	return out, err
}

func readJSONObjectsFromFile(path string) ([]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	if strings.HasSuffix(path, ".jsonl") {
		var out []any
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var item any
			if err := json.Unmarshal([]byte(line), &item); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			out = append(out, item)
		}
		return out, scanner.Err()
	}

	var value any
	if err := json.NewDecoder(f).Decode(&value); err != nil {
		return nil, err
	}
	switch typed := value.(type) {
	case []any:
		return typed, nil
	case map[string]any:
		if nodes, ok := typed["nodes"].([]any); ok {
			return nodes, nil
		}
		if receipts, ok := typed["receipts"].([]any); ok {
			return receipts, nil
		}
		return []any{typed}, nil
	default:
		return []any{typed}, nil
	}
}

func writeJSON(w http.ResponseWriter, body any) {
	writeJSONStatus(w, http.StatusOK, body)
}

func writeJSONStatus(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func init() {
	Register(Subcommand{Name: "control-room", Aliases: []string{}, Usage: "Launch the local evidence Control Room UI", RunFn: runControlRoom})
}
