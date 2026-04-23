package api

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type OSSLocalConfig struct {
	EvidenceDir string
	ReceiptsDir string
	Version     string
	BuildTime   string
}

type OSSLocalHandler struct {
	evidenceDir string
	receiptsDir string
	version     string
	buildTime   string
}

type OSSLocalRunSummary struct {
	Total            int    `json:"total"`
	LamportFinal     uint64 `json:"lamport_final"`
	RootHash         string `json:"root_hash,omitempty"`
	ChainVerified    bool   `json:"chain_verified"`
	LamportMonotonic bool   `json:"lamport_monotonic"`
	DenyPathTested   bool   `json:"deny_path_tested"`
	IsDemo           bool   `json:"is_demo"`
}

type OSSLocalDecision struct {
	ID           string `json:"id"`
	Source       string `json:"source"`
	Timestamp    string `json:"timestamp"`
	Principal    string `json:"principal,omitempty"`
	Action       string `json:"action,omitempty"`
	Tool         string `json:"tool,omitempty"`
	Verdict      string `json:"verdict,omitempty"`
	Status       string `json:"status,omitempty"`
	ReasonCode   string `json:"reason_code,omitempty"`
	Hash         string `json:"hash,omitempty"`
	PrevHash     string `json:"prev_hash,omitempty"`
	LamportClock uint64 `json:"lamport_clock,omitempty"`
}

type OSSLocalReplayReport struct {
	Version       string             `json:"version,omitempty"`
	SchemaVersion string             `json:"schema_version,omitempty"`
	GeneratedAt   string             `json:"generated_at,omitempty"`
	Template      string             `json:"template,omitempty"`
	Provider      string             `json:"provider,omitempty"`
	Summary       OSSLocalRunSummary `json:"summary"`
	Receipts      []OSSLocalDecision `json:"receipts"`
}

type OSSLocalSummaryResponse struct {
	Mode         string                `json:"mode"`
	Connected    bool                  `json:"connected"`
	GeneratedAt  string                `json:"generated_at"`
	Runtime      OSSLocalRuntimeStatus `json:"runtime"`
	Paths        OSSLocalPathsView     `json:"paths"`
	LatestReport *OSSLocalReportMeta   `json:"latest_report,omitempty"`
	Stats        OSSLocalStats         `json:"stats"`
}

type OSSLocalRuntimeStatus struct {
	Status    string `json:"status"`
	Version   string `json:"version,omitempty"`
	BuildTime string `json:"build_time,omitempty"`
}

type OSSLocalPathsView struct {
	EvidenceDir   string `json:"evidence_dir"`
	ReceiptsDir   string `json:"receipts_dir"`
	RunReportJSON string `json:"run_report_json"`
	RunReportHTML string `json:"run_report_html"`
	Proofgraph    string `json:"proofgraph"`
}

type OSSLocalReportMeta struct {
	Template    string             `json:"template,omitempty"`
	Provider    string             `json:"provider,omitempty"`
	GeneratedAt string             `json:"generated_at,omitempty"`
	Summary     OSSLocalRunSummary `json:"summary"`
}

type OSSLocalStats struct {
	ReceiptCount    int    `json:"receipt_count"`
	AllowCount      int    `json:"allow_count"`
	DenyCount       int    `json:"deny_count"`
	PendingCount    int    `json:"pending_count"`
	ProofgraphNodes int    `json:"proofgraph_nodes"`
	LastReceiptID   string `json:"last_receipt_id,omitempty"`
	LastReasonCode  string `json:"last_reason_code,omitempty"`
}

type OSSLocalTimelineResponse struct {
	Decisions []OSSLocalDecision `json:"decisions"`
	Total     int                `json:"total"`
	Source    string             `json:"source,omitempty"`
}

type OSSLocalCapabilitiesResponse struct {
	StudioMode string `json:"studio_mode"`
	ReadOnly   bool   `json:"read_only"`
	HTTPAPI    bool   `json:"http_api"`
	MCP        struct {
		Stdio     bool            `json:"stdio"`
		HTTP      bool            `json:"http"`
		AuthModes map[string]bool `json:"auth_modes"`
	} `json:"mcp"`
	Proxy struct {
		ReceiptsEndpoint   bool `json:"receipts_endpoint"`
		ProofgraphEndpoint bool `json:"proofgraph_endpoint"`
	} `json:"proxy"`
	Features struct {
		ImportRunReport        bool `json:"import_run_report"`
		OfflineVerify          bool `json:"offline_verify"`
		ProofReport            bool `json:"proof_report"`
		PackRegistry           bool `json:"pack_registry"`
		WorkspaceCollaboration bool `json:"workspace_collaboration"`
	} `json:"features"`
}

type ossLocalReportFile struct {
	Version       string                  `json:"version"`
	SchemaVersion string                  `json:"schema_version"`
	GeneratedAt   string                  `json:"generated_at"`
	Template      string                  `json:"template"`
	Provider      string                  `json:"provider"`
	Summary       OSSLocalRunSummary      `json:"summary"`
	Receipts      []ossLocalReportReceipt `json:"receipts"`
}

type ossLocalReportReceipt struct {
	ReceiptID  string            `json:"receipt_id"`
	Timestamp  string            `json:"timestamp"`
	Principal  string            `json:"principal"`
	Action     string            `json:"action"`
	Tool       string            `json:"tool,omitempty"`
	Verdict    string            `json:"verdict"`
	ReasonCode string            `json:"reason_code"`
	Hash       string            `json:"hash"`
	Lamport    uint64            `json:"lamport_clock"`
	PrevHash   string            `json:"prev_hash"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type ossLocalProxyReceipt struct {
	ReceiptID    string `json:"receipt_id"`
	Timestamp    string `json:"timestamp"`
	Model        string `json:"model,omitempty"`
	Status       string `json:"status"`
	ReasonCode   string `json:"reason_code,omitempty"`
	InputHash    string `json:"input_hash,omitempty"`
	OutputHash   string `json:"output_hash,omitempty"`
	LamportClock uint64 `json:"lamport_clock"`
	PrevHash     string `json:"prev_hash"`
}

func NewOSSLocalHandler(cfg OSSLocalConfig) *OSSLocalHandler {
	if strings.TrimSpace(cfg.EvidenceDir) == "" {
		cfg.EvidenceDir = "data/evidence"
	}
	if strings.TrimSpace(cfg.ReceiptsDir) == "" {
		cfg.ReceiptsDir = "helm-receipts"
	}
	return &OSSLocalHandler{
		evidenceDir: cfg.EvidenceDir,
		receiptsDir: cfg.ReceiptsDir,
		version:     cfg.Version,
		buildTime:   cfg.BuildTime,
	}
}

func (h *OSSLocalHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/oss-local/summary", h.HandleGetSummary)
	mux.HandleFunc("/api/v1/oss-local/decision-timeline", h.HandleGetTimeline)
	mux.HandleFunc("/api/v1/oss-local/receipts", h.HandleGetTimeline)
	mux.HandleFunc("/api/v1/oss-local/replay-report", h.HandleGetReplayReport)
	mux.HandleFunc("/api/v1/oss-local/proofgraph", h.HandleGetProofgraph)
	mux.HandleFunc("/api/v1/oss-local/capabilities", h.HandleGetCapabilities)
}

func (h *OSSLocalHandler) HandleGetSummary(w http.ResponseWriter, r *http.Request) {
	report, _ := h.loadReplayReport()
	timeline, source, _ := h.loadTimeline(200)

	stats := h.computeStats(timeline)
	stats.ProofgraphNodes = h.countProofgraphNodes()
	connected := report != nil || len(timeline) > 0

	resp := OSSLocalSummaryResponse{
		Mode:        "oss_local",
		Connected:   connected,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Runtime: OSSLocalRuntimeStatus{
			Status:    "ok",
			Version:   h.version,
			BuildTime: h.buildTime,
		},
		Paths: OSSLocalPathsView{
			EvidenceDir:   h.evidenceDir,
			ReceiptsDir:   h.receiptsDir,
			RunReportJSON: filepath.Join(h.evidenceDir, "run-report.json"),
			RunReportHTML: filepath.Join(h.evidenceDir, "run-report.html"),
			Proofgraph:    filepath.Join(h.receiptsDir, "proofgraph.json"),
		},
		Stats: stats,
	}
	if report != nil {
		resp.LatestReport = &OSSLocalReportMeta{
			Template:    report.Template,
			Provider:    report.Provider,
			GeneratedAt: report.GeneratedAt,
			Summary:     report.Summary,
		}
	}
	if source == "" && len(timeline) > 0 {
		resp.Connected = true
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *OSSLocalHandler) HandleGetTimeline(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	decisions, source, err := h.loadTimeline(limit)
	if err != nil {
		WriteInternal(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(OSSLocalTimelineResponse{
		Decisions: decisions,
		Total:     len(decisions),
		Source:    source,
	})
}

func (h *OSSLocalHandler) HandleGetReplayReport(w http.ResponseWriter, r *http.Request) {
	report, err := h.loadReplayReport()
	if err != nil {
		WriteInternal(w, err)
		return
	}

	if report == nil {
		decisions, _, timelineErr := h.loadTimeline(200)
		if timelineErr != nil {
			WriteInternal(w, timelineErr)
			return
		}
		report = &OSSLocalReplayReport{
			Version:     h.version,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Template:    "local-artifacts",
			Provider:    "file-backed",
			Summary:     h.buildSummaryFromTimeline(decisions),
			Receipts:    decisions,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
}

func (h *OSSLocalHandler) HandleGetProofgraph(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(h.receiptsDir, "proofgraph.json")
	data, err := os.ReadFile(path)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"nodes":   []any{},
			"path":    path,
			"status":  "unavailable",
			"message": "proofgraph.json not found yet",
		})
		return
	}

	var payload any
	if err := json.Unmarshal(data, &payload); err != nil {
		WriteInternal(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *OSSLocalHandler) HandleGetCapabilities(w http.ResponseWriter, r *http.Request) {
	var resp OSSLocalCapabilitiesResponse
	resp.StudioMode = "oss_local"
	resp.ReadOnly = true
	resp.HTTPAPI = true
	resp.MCP.Stdio = true
	resp.MCP.HTTP = true
	resp.MCP.AuthModes = map[string]bool{
		"none":          true,
		"static_header": true,
		"oauth":         false,
	}
	resp.Proxy.ReceiptsEndpoint = true
	resp.Proxy.ProofgraphEndpoint = true
	resp.Features.ImportRunReport = true
	resp.Features.OfflineVerify = true
	resp.Features.ProofReport = true
	resp.Features.PackRegistry = false
	resp.Features.WorkspaceCollaboration = false

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *OSSLocalHandler) loadReplayReport() (*OSSLocalReplayReport, error) {
	path := filepath.Join(h.evidenceDir, "run-report.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var report ossLocalReportFile
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}

	decisions := make([]OSSLocalDecision, 0, len(report.Receipts))
	for _, receipt := range report.Receipts {
		decisions = append(decisions, OSSLocalDecision{
			ID:           receipt.ReceiptID,
			Source:       "run-report",
			Timestamp:    receipt.Timestamp,
			Principal:    receipt.Principal,
			Action:       receipt.Action,
			Tool:         receipt.Tool,
			Verdict:      receipt.Verdict,
			Status:       receipt.Verdict,
			ReasonCode:   receipt.ReasonCode,
			Hash:         receipt.Hash,
			PrevHash:     receipt.PrevHash,
			LamportClock: receipt.Lamport,
		})
	}

	return &OSSLocalReplayReport{
		Version:       report.Version,
		SchemaVersion: report.SchemaVersion,
		GeneratedAt:   report.GeneratedAt,
		Template:      report.Template,
		Provider:      report.Provider,
		Summary:       report.Summary,
		Receipts:      decisions,
	}, nil
}

func (h *OSSLocalHandler) loadTimeline(limit int) ([]OSSLocalDecision, string, error) {
	report, err := h.loadReplayReport()
	if err != nil {
		return nil, "", err
	}
	if report != nil && len(report.Receipts) > 0 {
		return takeLatest(report.Receipts, limit), "run-report", nil
	}

	filePath, err := h.latestReceiptsFile()
	if err != nil {
		if os.IsNotExist(err) {
			return []OSSLocalDecision{}, "", nil
		}
		return nil, "", err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()

	var decisions []OSSLocalDecision
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var receipt ossLocalProxyReceipt
		if err := json.Unmarshal([]byte(line), &receipt); err != nil {
			return nil, "", err
		}
		decisions = append(decisions, OSSLocalDecision{
			ID:           receipt.ReceiptID,
			Source:       "proxy-jsonl",
			Timestamp:    receipt.Timestamp,
			Action:       "PROXY_RESPONSE",
			Tool:         receipt.Model,
			Verdict:      receipt.Status,
			Status:       receipt.Status,
			ReasonCode:   receipt.ReasonCode,
			Hash:         receipt.OutputHash,
			PrevHash:     receipt.PrevHash,
			LamportClock: receipt.LamportClock,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, "", err
	}

	sort.SliceStable(decisions, func(i, j int) bool {
		return decisions[i].LamportClock < decisions[j].LamportClock
	})
	return takeLatest(decisions, limit), "proxy-jsonl", nil
}

func takeLatest(decisions []OSSLocalDecision, limit int) []OSSLocalDecision {
	if limit <= 0 || len(decisions) <= limit {
		return decisions
	}
	return decisions[len(decisions)-limit:]
}

func (h *OSSLocalHandler) latestReceiptsFile() (string, error) {
	entries, err := os.ReadDir(h.receiptsDir)
	if err != nil {
		return "", err
	}
	var candidates []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "receipts-") || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		candidates = append(candidates, filepath.Join(h.receiptsDir, entry.Name()))
	}
	if len(candidates) == 0 {
		return "", os.ErrNotExist
	}
	sort.Strings(candidates)
	return candidates[len(candidates)-1], nil
}

func (h *OSSLocalHandler) countProofgraphNodes() int {
	path := filepath.Join(h.receiptsDir, "proofgraph.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	var payload any
	if err := json.Unmarshal(data, &payload); err != nil {
		return 0
	}

	switch typed := payload.(type) {
	case []any:
		return len(typed)
	case map[string]any:
		if nodes, ok := typed["nodes"].([]any); ok {
			return len(nodes)
		}
	}

	return 0
}

func (h *OSSLocalHandler) computeStats(decisions []OSSLocalDecision) OSSLocalStats {
	stats := OSSLocalStats{ReceiptCount: len(decisions)}
	for _, decision := range decisions {
		switch strings.ToUpper(decision.Verdict) {
		case "ALLOW", "APPROVED":
			stats.AllowCount++
		case "DENY":
			stats.DenyCount++
		case "PENDING":
			stats.PendingCount++
		}
		if decision.ID != "" {
			stats.LastReceiptID = decision.ID
		}
		if decision.ReasonCode != "" {
			stats.LastReasonCode = decision.ReasonCode
		}
	}
	return stats
}

func (h *OSSLocalHandler) buildSummaryFromTimeline(decisions []OSSLocalDecision) OSSLocalRunSummary {
	summary := OSSLocalRunSummary{Total: len(decisions)}
	if len(decisions) == 0 {
		return summary
	}

	summary.RootHash = decisions[len(decisions)-1].Hash
	summary.LamportFinal = decisions[len(decisions)-1].LamportClock
	summary.ChainVerified = true
	summary.LamportMonotonic = true

	var prevLamport uint64
	var prevHash string
	for i, decision := range decisions {
		if i > 0 {
			if prevHash != "" && decision.PrevHash != "" && decision.PrevHash != prevHash {
				summary.ChainVerified = false
			}
			if decision.LamportClock <= prevLamport {
				summary.LamportMonotonic = false
			}
		}
		if strings.EqualFold(decision.Verdict, "DENY") {
			summary.DenyPathTested = true
		}
		prevLamport = decision.LamportClock
		if decision.Hash != "" {
			prevHash = decision.Hash
		}
	}

	return summary
}
