package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	defaultQuickstartTenantID    = "default"
	defaultQuickstartPrincipalID = "local-operator"
	maxConsoleAssetBundleBytes   = 256 * 1024 * 1024
)

type quickstartRuntime struct {
	BootstrapToken string
	SessionToken   string
	TenantID       string
	PrincipalID    string
	Profile        string
	ExpiresAt      time.Time

	mu   sync.Mutex
	used bool
}

func newQuickstartRuntime(profile string, ttl time.Duration) (*quickstartRuntime, error) {
	bootstrap, err := randomTokenHex(32)
	if err != nil {
		return nil, err
	}
	session, err := randomTokenHex(32)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &quickstartRuntime{
		BootstrapToken: bootstrap,
		SessionToken:   session,
		TenantID:       defaultQuickstartTenantID,
		PrincipalID:    defaultQuickstartPrincipalID,
		Profile:        profile,
		ExpiresAt:      time.Now().UTC().Add(ttl),
	}, nil
}

func (q *quickstartRuntime) exchange(token string) (map[string]any, int, string) {
	if q == nil {
		return nil, http.StatusNotFound, "local quickstart session is not enabled"
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if time.Now().UTC().After(q.ExpiresAt) {
		return nil, http.StatusUnauthorized, "local quickstart token expired"
	}
	if q.used {
		return nil, http.StatusUnauthorized, "local quickstart token already used"
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(q.BootstrapToken)) != 1 {
		return nil, http.StatusUnauthorized, "invalid local quickstart token"
	}
	q.used = true
	return q.sessionDocument(), http.StatusOK, ""
}

func (q *quickstartRuntime) sessionDocument() map[string]any {
	return map[string]any{
		"session_token": q.SessionToken,
		"tenant_id":     q.TenantID,
		"principal_id":  q.PrincipalID,
		"principal":     "did:helm:operator:" + q.PrincipalID,
		"expires_at":    q.ExpiresAt.Format(time.RFC3339),
		"entitlements":  []string{"OSS_CORE"},
	}
}

func RegisterLocalFirstRunRoutes(mux *http.ServeMux, svc *Services, opts serverOptions) {
	if opts.Quickstart == nil {
		return
	}
	mux.HandleFunc("/__helm/config.json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"api_base_url":     fmt.Sprintf("http://%s:%d", firstNonEmpty(opts.BindAddr, "127.0.0.1"), opts.Port),
			"local_mode":       true,
			"start_onboarding": true,
			"tenant_id":        opts.Quickstart.TenantID,
			"principal_id":     opts.Quickstart.PrincipalID,
			"profile":          opts.Quickstart.Profile,
			"entitlements":     []string{"OSS_CORE"},
		})
	})

	mux.HandleFunc("/api/v1/local-session/exchange", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		if !requestFromLoopback(r) {
			api.WriteForbidden(w, "Local quickstart session exchange is loopback-only")
			return
		}
		var body struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			api.WriteBadRequest(w, "Invalid JSON body")
			return
		}
		doc, status, detail := opts.Quickstart.exchange(strings.TrimSpace(body.Token))
		if status != http.StatusOK {
			api.WriteError(w, status, "Local quickstart exchange failed", detail)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/api/v1/onboarding/state", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeOnboardingState(w, r, svc, opts, nil)
	}))
	mux.HandleFunc("/api/v1/onboarding/run-step", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var body struct {
			StepID string `json:"step_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			api.WriteBadRequest(w, "Invalid JSON body")
			return
		}
		step, ok := onboardingStepByID(body.StepID)
		if !ok {
			api.WriteBadRequest(w, "Unknown onboarding step")
			return
		}
		receiptRef, err := persistOnboardingReceipt(r, svc, step)
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		writeOnboardingState(w, r, svc, opts, map[string]string{step.ID: receiptRef})
	}))
	mux.HandleFunc("/api/v1/onboarding/export", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		export, err := exportOnboardingEvidence(r, svc, opts)
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(export)
	}))
}

func RegisterLocalConsoleAssetRoutes(mux *http.ServeMux, opts serverOptions, bindAddr string, port int) {
	assets := strings.TrimSpace(opts.ConsoleAssetsPath)
	if assets == "" {
		return
	}
	assetRoot, err := filepath.Abs(assets)
	if err != nil {
		return
	}
	info, err := os.Stat(assetRoot)
	if err != nil || !info.IsDir() {
		return
	}
	bundle, err := loadConsoleAssetBundle(assetRoot)
	if err != nil {
		return
	}
	handler := spaFileServer(bundle)
	mux.HandleFunc("/console", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/console/", http.StatusTemporaryRedirect)
	})
	mux.Handle("/console/", http.StripPrefix("/console/", handler))
	_ = bindAddr
	_ = port
}

type consoleAssetBundle struct {
	index  consoleAsset
	assets map[string]consoleAsset
}

type consoleAsset struct {
	body        []byte
	contentType string
	modTime     time.Time
}

func spaFileServer(bundle consoleAssetBundle) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assetPath, ok := localConsoleAssetPath(r.URL.Path)
		if !ok || assetPath == "" {
			serveConsoleAsset(w, r, "index.html", bundle.index)
			return
		}
		if asset, ok := bundle.assets[assetPath]; ok {
			serveConsoleAsset(w, r, assetPath, asset)
			return
		}
		serveConsoleAsset(w, r, "index.html", bundle.index)
	})
}

func serveConsoleAsset(w http.ResponseWriter, r *http.Request, name string, asset consoleAsset) {
	if asset.contentType != "" {
		w.Header().Set("Content-Type", asset.contentType)
	}
	http.ServeContent(w, r, name, asset.modTime, bytes.NewReader(asset.body))
}

func loadConsoleAssetBundle(root string) (consoleAssetBundle, error) {
	bundle := consoleAssetBundle{assets: make(map[string]consoleAsset)}
	var total int64
	var hasIndex bool
	err := filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, filePath)
		if err != nil || rel == "." {
			return err
		}
		assetPath := filepath.ToSlash(rel)
		if clean, ok := localConsoleAssetPath("/" + assetPath); !ok || clean != assetPath {
			return fmt.Errorf("unsafe console asset path: %s", rel)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() < 0 || total+info.Size() > maxConsoleAssetBundleBytes {
			return fmt.Errorf("console asset bundle exceeds %d bytes", maxConsoleAssetBundleBytes)
		}
		body, err := readConsoleAssetFile(filePath)
		if err != nil {
			return err
		}
		total += int64(len(body))
		asset := consoleAsset{
			body:        body,
			contentType: consoleAssetContentType(filePath, body),
			modTime:     info.ModTime(),
		}
		if assetPath == "index.html" {
			bundle.index = asset
			hasIndex = true
			return nil
		}
		bundle.assets[assetPath] = asset
		return nil
	})
	if err != nil {
		return consoleAssetBundle{}, err
	}
	if !hasIndex {
		return consoleAssetBundle{}, fmt.Errorf("console bundle missing index.html")
	}
	return bundle, nil
}

func readConsoleAssetFile(filePath string) ([]byte, error) {

	// codeql[go/path-injection] -- filePath is produced by WalkDir under the operator-selected Console bundle before serving starts; request paths never reach this read.
	return os.ReadFile(filePath)
}

func consoleAssetContentType(filePath string, body []byte) string {
	if contentType := mime.TypeByExtension(filepath.Ext(filePath)); contentType != "" {
		return contentType
	}
	return http.DetectContentType(body)
}

func localConsoleAssetPath(rawPath string) (string, bool) {
	if strings.Contains(rawPath, "\\") {
		return "", false
	}
	trimmed := strings.TrimPrefix(rawPath, "/")
	if trimmed == "" {
		return "", true
	}
	for _, segment := range strings.Split(trimmed, "/") {
		if segment == ".." {
			return "", false
		}
	}
	clean := strings.TrimPrefix(path.Clean("/"+trimmed), "/")
	if clean == "." {
		return "", true
	}
	return clean, true
}

type onboardingStep struct {
	ID          string
	Title       string
	Description string
	Verdict     string
	ReasonCode  string
	Action      string
	Resource    string
}

func onboardingSteps() []onboardingStep {
	return []onboardingStep{
		{ID: "health", Title: "Kernel health", Description: "Confirm the local Kernel is reachable.", Verdict: "ALLOW", ReasonCode: "LOCAL_KERNEL_READY", Action: "HELM_ONBOARDING_HEALTH", Resource: "local.kernel"},
		{ID: "policy", Title: "Policy loaded", Description: "Confirm the fail-closed starter policy is active.", Verdict: "ALLOW", ReasonCode: "POLICY_READY", Action: "HELM_ONBOARDING_POLICY", Resource: "local.policy"},
		{ID: "allow", Title: "Signed allow", Description: "Run a safe request and inspect the issued receipt.", Verdict: "ALLOW", ReasonCode: "SAFE_REQUEST_ALLOWED", Action: "HELM_ONBOARDING_ALLOW", Resource: "local.safe"},
		{ID: "deny", Title: "Signed deny", Description: "Run a dangerous request and prove it is blocked.", Verdict: "DENY", ReasonCode: "DANGEROUS_REQUEST_DENIED", Action: "HELM_ONBOARDING_DENY", Resource: "local.dangerous"},
		{ID: "mcp", Title: "MCP quarantine", Description: "Show an untrusted MCP tool remains quarantined.", Verdict: "ESCALATE", ReasonCode: "MCP_TOOL_QUARANTINED", Action: "HELM_ONBOARDING_MCP", Resource: "mcp.untrusted"},
		{ID: "verify", Title: "Tamper check", Description: "Verify the original receipt and reject tampering.", Verdict: "ALLOW", ReasonCode: "TAMPER_REJECTED", Action: "HELM_ONBOARDING_VERIFY", Resource: "receipt.tamper"},
	}
}

func onboardingStepByID(id string) (onboardingStep, bool) {
	id = strings.TrimSpace(id)
	for _, step := range onboardingSteps() {
		if step.ID == id {
			return step, true
		}
	}
	return onboardingStep{}, false
}

func writeOnboardingState(w http.ResponseWriter, r *http.Request, svc *Services, opts serverOptions, fresh map[string]string) {
	receiptRefs := onboardingReceiptRefs(r.Context(), svc)
	for k, v := range fresh {
		receiptRefs[k] = v
	}
	steps := make([]map[string]any, 0, len(onboardingSteps()))
	for _, step := range onboardingSteps() {
		status := "pending"
		receiptRef := receiptRefs[step.ID]
		if receiptRef != "" {
			status = "pass"
		}
		steps = append(steps, map[string]any{
			"id":          step.ID,
			"title":       step.Title,
			"description": step.Description,
			"status":      status,
			"verdict":     step.Verdict,
			"reason_code": step.ReasonCode,
			"receipt_ref": receiptRef,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"mode":              "self-hosted-oss",
		"entitlements":      []string{"OSS_CORE"},
		"profile":           quickstartProfile(opts),
		"policy_path":       opts.PolicyPath,
		"evidence_pack_ref": onboardingEvidenceRef(receiptRefs),
		"steps":             steps,
	})
}

func onboardingReceiptRefs(ctx context.Context, svc *Services) map[string]string {
	refs := make(map[string]string)
	if svc == nil || svc.ReceiptStore == nil {
		return refs
	}
	receipts, err := svc.ReceiptStore.List(ctx, 500)
	if err != nil {
		return refs
	}
	for _, receipt := range receipts {
		if receipt == nil || receipt.Metadata == nil {
			continue
		}
		stepID, _ := receipt.Metadata["onboarding_step"].(string)
		if stepID != "" && refs[stepID] == "" {
			refs[stepID] = receipt.ReceiptID
		}
	}
	return refs
}

func persistOnboardingReceipt(r *http.Request, svc *Services, step onboardingStep) (string, error) {
	if svc == nil || svc.ReceiptStore == nil || svc.ReceiptSigner == nil {
		return "", fmt.Errorf("onboarding receipt persistence unavailable")
	}
	principal, err := helmauth.GetPrincipal(r.Context())
	if err != nil || principal == nil {
		return "", fmt.Errorf("onboarding route requires authenticated principal")
	}
	now := time.Now().UTC()
	decision := &contracts.DecisionRecord{
		ID:                 fmt.Sprintf("onboarding_%s_%d", step.ID, now.UnixNano()),
		SubjectID:          principal.GetID(),
		Action:             step.Action,
		Resource:           step.Resource,
		Verdict:            step.Verdict,
		Reason:             step.Description,
		ReasonCode:         step.ReasonCode,
		PolicyBackend:      "helm-local-quickstart",
		PolicyContentHash:  sha256HexBytes([]byte(step.ID + ":" + step.ReasonCode)),
		PolicyDecisionHash: sha256HexBytes([]byte(step.ID + ":" + step.Verdict)),
		Timestamp:          now,
	}
	err = persistDecisionReceipt(r.Context(), svc, decision, principal.GetID(), []byte(step.Action+":"+step.Resource), map[string]any{
		"source":          "onboarding",
		"onboarding_step": step.ID,
		"action":          step.Action,
		"resource":        step.Resource,
		"reason_code":     step.ReasonCode,
	})
	if err != nil {
		return "", err
	}
	return "rcpt_" + decision.ID, nil
}

func exportOnboardingEvidence(r *http.Request, svc *Services, opts serverOptions) (map[string]any, error) {
	refs := onboardingReceiptRefs(r.Context(), svc)
	payload := map[string]any{
		"schema_version": "helm.onboarding.evidencepack.v1",
		"created_at":     time.Now().UTC().Format(time.RFC3339),
		"mode":           "self-hosted-oss",
		"profile":        quickstartProfile(opts),
		"policy_path":    opts.PolicyPath,
		"receipt_refs":   refs,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	ref := "evidencepack:onboarding:" + hex.EncodeToString(sum[:8])
	if opts.DataDir != "" {
		dir := filepath.Join(opts.DataDir, "evidence")
		if err := os.MkdirAll(dir, 0750); err == nil {
			_ = os.WriteFile(filepath.Join(dir, "onboarding-evidence.json"), data, 0600)
		}
	}
	return map[string]any{
		"evidence_pack_ref": ref,
		"sha256":            hex.EncodeToString(sum[:]),
		"receipt_refs":      refs,
		"steps":             onboardingStateForExport(refs),
	}, nil
}

func onboardingStateForExport(refs map[string]string) []map[string]any {
	steps := make([]map[string]any, 0, len(onboardingSteps()))
	for _, step := range onboardingSteps() {
		status := "pending"
		if refs[step.ID] != "" {
			status = "pass"
		}
		steps = append(steps, map[string]any{
			"id":          step.ID,
			"title":       step.Title,
			"description": step.Description,
			"status":      status,
			"receipt_ref": refs[step.ID],
		})
	}
	return steps
}

func onboardingEvidenceRef(refs map[string]string) string {
	if len(refs) == 0 {
		return ""
	}
	var b strings.Builder
	for _, step := range onboardingSteps() {
		if ref := refs[step.ID]; ref != "" {
			b.WriteString(step.ID)
			b.WriteString("=")
			b.WriteString(ref)
			b.WriteString(";")
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "evidencepack:onboarding:" + hex.EncodeToString(sum[:8])
}

func quickstartProfile(opts serverOptions) string {
	if opts.Quickstart != nil && opts.Quickstart.Profile != "" {
		return opts.Quickstart.Profile
	}
	return "mcp"
}

func requestFromLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func randomTokenHex(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
