package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/account"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	lpimporter "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/importer"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/readmodel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/repair"
	lpsecrets "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/secrets"
	launchsession "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

type launchpadPlanRequest struct {
	AppID       string `json:"app_id"`
	SubstrateID string `json:"substrate_id"`
	Principal   string `json:"principal"`
}

func RegisterLaunchpadRoutes(mux *http.ServeMux, svc *Services) {
	mux.HandleFunc("/api/v1/launchpad/", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/launchpad/"), "/")
		catalog, err := registry.LoadCatalog("")
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		if err := catalog.Validate(); err != nil {
			api.WriteInternal(w, err)
			return
		}

		store := launchpadStoreForService(svc)
		switch {
		case path == "apps" && r.Method == http.MethodGet:
			statuses, _ := lpsecrets.NewStore(store.Root()).Statuses()
			runs, _ := store.List()
			apps := readmodel.RegistryApps(catalog, statuses, runs)
			if ok := attachAppEntitlements(w, r, apps, catalog, store); !ok {
				return
			}
			writeLaunchpadJSON(w, http.StatusOK, map[string]any{"apps": apps, "registry_apps": apps})
		case path == "substrates" && r.Method == http.MethodGet:
			writeLaunchpadJSON(w, http.StatusOK, map[string]any{"substrates": catalog.Substrates})
		case path == "matrix" && r.Method == http.MethodGet:
			matrix := catalog.Matrix()
			if ok := attachMatrixEntitlements(w, r, matrix, store); !ok {
				return
			}
			writeLaunchpadJSON(w, http.StatusOK, map[string]any{"matrix": matrix})
		case path == "plan" && r.Method == http.MethodPost:
			handleLaunchpadPlan(w, r, catalog, store)
		case path == "launch" && r.Method == http.MethodPost:
			handleLaunchpadLaunch(w, r, catalog, store)
		case path == "imports" && r.Method == http.MethodGet:
			handleLaunchpadImportsList(w, store)
		case path == "imports" && r.Method == http.MethodPost:
			handleLaunchpadImportCreate(w, r, catalog, store)
		case strings.HasPrefix(path, "imports/"):
			handleLaunchpadImportPath(w, r, strings.TrimPrefix(path, "imports/"), store)
		case path == "runs" && r.Method == http.MethodGet:
			handleLaunchpadRunsList(w, store)
		case path == "runs" && r.Method == http.MethodPost:
			handleLaunchpadRunCreate(w, r, catalog, store)
		case path == "policy/simulate" && r.Method == http.MethodPost:
			handleLaunchpadPolicySimulate(w, r, catalog, store)
		case strings.HasPrefix(path, "sandbox/") && r.Method == http.MethodGet:
			handleLaunchpadSandbox(w, r, strings.TrimPrefix(path, "sandbox/"), catalog, store)
		case path == "mcp/threat-reviews" && r.Method == http.MethodGet:
			runs, _ := store.List()
			writeLaunchpadJSON(w, http.StatusOK, map[string]any{
				"threat_reviews": readmodel.MCPThreatReviews(catalog, runs),
				"cli_equivalent": "helm-ai-kernel mcp quarantine",
			})
		case path == "mcp/approvals" && r.Method == http.MethodPost:
			handleLaunchpadMCPApproval(w, r)
		case strings.HasPrefix(path, "runs/"):
			handleLaunchpadRunsPath(w, r, strings.TrimPrefix(path, "runs/"), catalog, store)
		case path == "secrets" && (r.Method == http.MethodGet || r.Method == http.MethodPost):
			handleLaunchpadSecrets(w, r, store)
		case strings.HasPrefix(path, "launches/"):
			handleLaunchpadRunPath(w, r, strings.TrimPrefix(path, "launches/"), store)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))
}

func launchpadStoreForService(svc *Services) *launchsession.Store {
	if svc != nil && svc.LaunchpadStore != nil {
		return svc.LaunchpadStore
	}
	dataDir := ""
	if svc != nil {
		dataDir = svc.DataDir
	}
	return launchsession.NewStore(launchpadStoreRoot(dataDir))
}

func handleLaunchpadPlan(w http.ResponseWriter, r *http.Request, catalog *registry.Catalog, store *launchsession.Store) {
	req, ok := decodeLaunchpadPlanRequest(w, r)
	if !ok {
		return
	}
	compiled, err := compileLaunchpadPlan(catalog, req, store)
	if err != nil {
		compiled.ReasonCode = firstNonEmpty(compiled.ReasonCode, err.Error())
	}
	if ok := attachPlanEntitlements(w, r, &compiled, req, store); !ok {
		return
	}
	writeLaunchpadJSON(w, http.StatusAccepted, compiled)
}

func handleLaunchpadLaunch(w http.ResponseWriter, r *http.Request, catalog *registry.Catalog, store *launchsession.Store) {
	req, ok := decodeLaunchpadPlanRequest(w, r)
	if !ok {
		return
	}
	if ok := requireLaunchpadEntitlement(w, r, "launch", req.AppID, req.SubstrateID, "", store); !ok {
		return
	}
	compiled, err := compileLaunchpadPlan(catalog, req, store)
	if err != nil {
		compiled.ReasonCode = firstNonEmpty(compiled.ReasonCode, err.Error())
	}
	run, saveErr := launchsession.NewExecutor(store).ExecuteLaunch(compiled, launchsession.ExecuteOptions{Reason: "launch requested through OSS Console API"})
	if saveErr != nil {
		api.WriteInternal(w, saveErr)
		return
	}
	writeLaunchpadJSON(w, http.StatusAccepted, run)
}

func handleLaunchpadImportsList(w http.ResponseWriter, store *launchsession.Store) {
	records, err := lpimporter.NewStore(store.Root()).List()
	if err != nil {
		api.WriteInternal(w, err)
		return
	}
	writeLaunchpadJSON(w, http.StatusOK, map[string]any{
		"imports":        records,
		"cli_equivalent": "helm-ai-kernel launchpad imports list",
	})
}

func handleLaunchpadImportCreate(w http.ResponseWriter, r *http.Request, catalog *registry.Catalog, store *launchsession.Store) {
	var req lpimporter.ImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteBadRequest(w, "invalid launchpad import request")
		return
	}
	adapters, err := lpimporter.LoadAdapters(catalog.Root)
	if err != nil {
		api.WriteInternal(w, err)
		return
	}
	record, err := lpimporter.NewAnalyzer(adapters, nil).Import(r.Context(), req, time.Now().UTC())
	if err != nil {
		api.WriteBadRequest(w, err.Error())
		return
	}
	if err := lpimporter.NewStore(store.Root()).Save(record); err != nil {
		api.WriteInternal(w, err)
		return
	}
	writeLaunchpadJSON(w, http.StatusAccepted, map[string]any{
		"import":         record,
		"cli_equivalent": record.LaunchRecipe.CLIEquivalent,
	})
}

func handleLaunchpadImportPath(w http.ResponseWriter, r *http.Request, rest string, store *launchsession.Store) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		api.WriteBadRequest(w, "import id required")
		return
	}
	importStore := lpimporter.NewStore(store.Root())
	record, err := importStore.Get(parts[0])
	if err != nil {
		api.WriteError(w, http.StatusNotFound, "Import not found", err.Error())
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		writeLaunchpadJSON(w, http.StatusOK, map[string]any{"import": record})
		return
	}
	if len(parts) != 2 || r.Method != http.MethodPost {
		api.WriteMethodNotAllowed(w)
		return
	}
	switch parts[1] {
	case "preflight":
		record = lpimporter.Preflight(record, time.Now().UTC())
		if err := importStore.Save(record); err != nil {
			api.WriteInternal(w, err)
			return
		}
		writeLaunchpadJSON(w, http.StatusAccepted, map[string]any{
			"import":         record,
			"preflight":      record.Preflight,
			"cli_equivalent": "helm-ai-kernel launchpad imports " + record.ID + " preflight",
		})
	case "promote":
		handleLaunchpadImportPromote(w, record)
	case "launch":
		handleLaunchpadImportLaunch(w, record)
	case "teardown":
		record.State = lpimporter.StateTornDown
		record.EvidenceLedger.Status = "teardown_recorded"
		if err := importStore.Save(record); err != nil {
			api.WriteInternal(w, err)
			return
		}
		writeLaunchpadJSON(w, http.StatusAccepted, map[string]any{
			"import":         record,
			"cli_equivalent": "helm-ai-kernel launchpad imports " + record.ID + " teardown",
		})
	default:
		api.WriteMethodNotAllowed(w)
	}
}

func handleLaunchpadImportPromote(w http.ResponseWriter, record lpimporter.ImportRecord) {
	status := ""
	if record.Preflight != nil {
		status = record.Preflight.Status
	}
	if record.State != lpimporter.StatePromotable || status != "PASS" {
		api.WriteError(w, http.StatusConflict, "Import is not promotable", "promotion requires sandbox preflight PASS, SBOM, vulnerability scan, license review, smoke test, and teardown evidence")
		return
	}
	writeLaunchpadJSON(w, http.StatusAccepted, map[string]any{
		"promotion_state":        record.LaunchRecipe.PromotionState,
		"generated_app_specs":    record.LaunchRecipe.GeneratedAppSpecs,
		"promotion_requirements": record.LaunchRecipe.PromotionRequirements,
		"message":                "Promotion is evidence-gated. This endpoint returns the generated AppSpec candidate but does not write a trusted registry entry.",
		"cli_equivalent":         "helm-ai-kernel launchpad imports " + record.ID + " promote",
	})
}

func handleLaunchpadImportLaunch(w http.ResponseWriter, record lpimporter.ImportRecord) {
	api.WriteError(w, http.StatusConflict, "Imported app is not launchable yet", "generated imports must be promoted to the registry with preflight evidence before LaunchKit execution")
}

func handleLaunchpadRunsList(w http.ResponseWriter, store *launchsession.Store) {
	runs, err := store.List()
	if err != nil {
		api.WriteInternal(w, err)
		return
	}
	instances := make([]readmodel.RuntimeInstance, 0, len(runs))
	for _, run := range runs {
		instances = append(instances, readmodel.RuntimeFromRun(run))
	}
	writeLaunchpadJSON(w, http.StatusOK, map[string]any{"runs": runs, "instances": instances})
}

func handleLaunchpadRunCreate(w http.ResponseWriter, r *http.Request, catalog *registry.Catalog, store *launchsession.Store) {
	req, ok := decodeLaunchpadPlanRequest(w, r)
	if !ok {
		return
	}
	if ok := requireLaunchpadEntitlement(w, r, "create_run", req.AppID, req.SubstrateID, "", store); !ok {
		return
	}
	app, appOK := catalog.App(req.AppID)
	substrate, substrateOK := catalog.Substrate(req.SubstrateID)
	compiled, err := compileLaunchpadPlan(catalog, req, store)
	if err != nil {
		compiled.ReasonCode = firstNonEmpty(compiled.ReasonCode, err.Error())
	}
	run, saveErr := launchsession.NewExecutor(store).ExecuteLaunch(compiled, launchsession.ExecuteOptions{Reason: "run requested through OSS Console API"})
	if saveErr != nil {
		api.WriteInternal(w, saveErr)
		return
	}
	if !appOK || !substrateOK {
		writeLaunchpadJSON(w, http.StatusAccepted, map[string]any{"run": run, "instance": readmodel.RuntimeFromRun(run), "events": readmodel.EventsFromRun(run)})
		return
	}
	writeLaunchpadJSON(w, http.StatusAccepted, readmodel.Detail(app, substrate, compiled, run))
}

func handleLaunchpadRunsPath(w http.ResponseWriter, r *http.Request, rest string, catalog *registry.Catalog, store *launchsession.Store) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		api.WriteBadRequest(w, "run id required")
		return
	}
	runID := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		run, err := store.Get(runID)
		if err != nil {
			api.WriteError(w, http.StatusNotFound, "Run not found", err.Error())
			return
		}
		writeLaunchpadJSON(w, http.StatusOK, detailForStoredRun(catalog, run))
		return
	}
	if len(parts) == 2 && parts[1] == "events" && r.Method == http.MethodGet {
		run, err := store.Get(runID)
		if err != nil {
			api.WriteError(w, http.StatusNotFound, "Run not found", err.Error())
			return
		}
		writeLaunchpadJSON(w, http.StatusOK, map[string]any{"events": readmodel.EventsFromRun(run)})
		return
	}
	if len(parts) == 2 && parts[1] == "receipts" && r.Method == http.MethodGet {
		run, err := store.Get(runID)
		if err != nil {
			api.WriteError(w, http.StatusNotFound, "Run not found", err.Error())
			return
		}
		writeLaunchpadJSON(w, http.StatusOK, map[string]any{
			"run_id":         runID,
			"receipts":       readmodel.ReceiptRefs(run),
			"proof_status":   proofStatusForRefs(readmodel.ReceiptRefs(run)),
			"cli_equivalent": "helm-ai-kernel run receipts " + runID,
		})
		return
	}
	if len(parts) == 2 && parts[1] == "logs" && r.Method == http.MethodGet {
		run, err := store.Get(runID)
		if err != nil {
			api.WriteError(w, http.StatusNotFound, "Run not found", err.Error())
			return
		}
		logBytes, readErr := store.ReadLog(runID)
		logText := ""
		proofStatus := "unproven"
		if readErr == nil {
			logText = string(logBytes)
			proofStatus = "proven"
		}
		writeLaunchpadJSON(w, http.StatusOK, map[string]any{
			"run_id":         runID,
			"log":            logText,
			"log_path":       run.LogPath,
			"proof_status":   proofStatus,
			"cli_equivalent": "helm-ai-kernel run logs " + runID,
		})
		return
	}
	if len(parts) == 3 && parts[1] == "evidence" && parts[2] == "export" && r.Method == http.MethodPost {
		run, err := store.Get(runID)
		if err != nil {
			api.WriteError(w, http.StatusNotFound, "Run not found", err.Error())
			return
		}
		if ok := requireLaunchpadEntitlement(w, r, "evidence_export", run.AppID, run.SubstrateID, runID, store); !ok {
			return
		}
		writeLaunchpadJSON(w, http.StatusAccepted, map[string]any{
			"run_id":                  runID,
			"evidencepack_refs":       run.EvidencePackRefs,
			"evidencepack_ref":        lastString(run.EvidencePackRefs),
			"offline_verify_command":  run.VerificationCommand,
			"offline_verification":    run.VerificationCommand != "",
			"local_verification":      run.VerificationCommand != "",
			"proof_status":            proofStatusForRefs(run.EvidencePackRefs),
			"cli_equivalent":          "helm-ai-kernel evidence export " + runID,
			"verify_cli_equivalent":   firstNonEmpty(run.VerificationCommand, "helm-ai-kernel verify --bundle <file>"),
			"without_cloud_supported": true,
		})
		return
	}
	if len(parts) == 2 && parts[1] == "teardown" && r.Method == http.MethodPost {
		if _, err := store.Get(runID); err != nil {
			api.WriteError(w, http.StatusNotFound, "Run not found", err.Error())
			return
		}
		deleted, err := launchsession.NewExecutor(store).DeleteLaunch(runID, true)
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		writeLaunchpadJSON(w, http.StatusAccepted, detailForStoredRun(catalog, deleted))
		return
	}
	api.WriteMethodNotAllowed(w)
}

func handleLaunchpadPolicySimulate(w http.ResponseWriter, r *http.Request, catalog *registry.Catalog, store *launchsession.Store) {
	req, ok := decodeLaunchpadPlanRequest(w, r)
	if !ok {
		return
	}
	if ok := requireLaunchpadEntitlement(w, r, "custom_policy", req.AppID, req.SubstrateID, "", store); !ok {
		return
	}
	app, appOK := catalog.App(req.AppID)
	if !appOK {
		api.WriteError(w, http.StatusNotFound, "App not found", req.AppID)
		return
	}
	compiled, err := compileLaunchpadPlan(catalog, req, store)
	if err != nil {
		compiled.ReasonCode = firstNonEmpty(compiled.ReasonCode, err.Error())
	}
	writeLaunchpadJSON(w, http.StatusAccepted, readmodel.PolicySimulationForApp(app, compiled))
}

func handleLaunchpadSandbox(w http.ResponseWriter, _ *http.Request, rest string, catalog *registry.Catalog, store *launchsession.Store) {
	runID := strings.Trim(rest, "/")
	if runID == "" {
		api.WriteBadRequest(w, "run id required")
		return
	}
	run, err := store.Get(runID)
	if err != nil {
		api.WriteError(w, http.StatusNotFound, "Run not found", err.Error())
		return
	}
	grant := readmodel.RuntimeFromRun(run).SandboxGrant
	if app, ok := catalog.App(run.AppID); ok {
		if substrate, substrateOK := catalog.Substrate(run.SubstrateID); substrateOK {
			grant = readmodel.SandboxGrant(app, substrate, run)
		}
	}
	writeLaunchpadJSON(w, http.StatusOK, map[string]any{
		"run_id":         runID,
		"sandbox_grant":  grant,
		"cli_equivalent": "helm-ai-kernel sandbox inspect " + runID,
	})
}

func handleLaunchpadMCPApproval(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID  string   `json:"server_id"`
		Tools     []string `json:"tools"`
		TTL       string   `json:"ttl"`
		Reason    string   `json:"reason"`
		Approver  string   `json:"approver"`
		Revocable bool     `json:"revocable"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteBadRequest(w, "invalid MCP approval request")
		return
	}
	req.ServerID = strings.TrimSpace(req.ServerID)
	req.Reason = strings.TrimSpace(req.Reason)
	tools, err := normalizeMCPApprovalTools(req.Tools)
	if err != nil {
		api.WriteBadRequest(w, err.Error())
		return
	}
	if req.ServerID == "" || len(tools) == 0 || req.Reason == "" {
		api.WriteBadRequest(w, "server_id, tools, and reason are required")
		return
	}
	if req.TTL == "" {
		req.TTL = "1h"
	}
	if req.Approver == "" {
		req.Approver = "local.operator"
	}
	ttl, err := time.ParseDuration(req.TTL)
	if err != nil || ttl <= 0 {
		api.WriteBadRequest(w, "ttl must be a positive duration")
		return
	}
	now := time.Now().UTC()
	expiration := now.Add(ttl).Format(time.RFC3339)
	toolScopeHash := mcpApprovalToolScopeHash(tools)
	receiptID := "rcp_mcp_approval_" + sanitizeReceiptPart(req.ServerID+"_"+strings.Join(tools, "_")+"_"+toolScopeHash)
	writeLaunchpadJSON(w, http.StatusCreated, map[string]any{
		"approval": map[string]any{
			"server_id":             req.ServerID,
			"tool_names":            tools,
			"tool_scope_hash":       toolScopeHash,
			"risk":                  "scoped-operator-approved",
			"approver":              req.Approver,
			"reason":                req.Reason,
			"receipt_id":            receiptID,
			"expires_at":            expiration,
			"revocation_semantics":  "revocable by helm-ai-kernel mcp quarantine or policy epoch change",
			"side_effects_allowed":  true,
			"raw_secret_disclosure": false,
		},
		"cli_equivalent": "helm-ai-kernel mcp approve " + req.ServerID + " --tools " + strings.Join(tools, ",") + " --ttl " + req.TTL + " --reason " + shellQuote(req.Reason),
	})
}

func normalizeMCPApprovalTools(input []string) ([]string, error) {
	seen := map[string]bool{}
	tools := make([]string, 0, len(input))
	for _, tool := range input {
		tool = strings.TrimSpace(tool)
		if tool == "" || tool == "*" {
			return nil, fmt.Errorf("tools must name explicit MCP tools")
		}
		if strings.ContainsAny(tool, " \t\r\n") {
			return nil, fmt.Errorf("tools must not contain whitespace")
		}
		if !seen[tool] {
			seen[tool] = true
			tools = append(tools, tool)
		}
	}
	sort.Strings(tools)
	return tools, nil
}

func mcpApprovalToolScopeHash(tools []string) string {
	normalized := append([]string(nil), tools...)
	sort.Strings(normalized)
	sum := sha256.Sum256([]byte(strings.Join(normalized, "\n")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func handleLaunchpadSecrets(w http.ResponseWriter, r *http.Request, store *launchsession.Store) {
	secretStore := lpsecrets.NewStore(store.Root())
	if r.Method == http.MethodGet {
		statuses, err := secretStore.Statuses()
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		writeLaunchpadJSON(w, http.StatusOK, map[string]any{"secrets": readmodel.SecretGrantStatuses(statuses)})
		return
	}
	if ok := requireLaunchpadEntitlement(w, r, "bring_own_secrets", "", "", "", store); !ok {
		return
	}
	var req struct {
		Name     string `json:"name"`
		Provider string `json:"provider"`
		ValueEnv string `json:"value_env"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteBadRequest(w, "invalid secret binding request")
		return
	}
	binding, err := secretStore.Set(req.Name, req.Provider, req.ValueEnv)
	if err != nil {
		api.WriteBadRequest(w, err.Error())
		return
	}
	statuses, _ := secretStore.Statuses()
	writeLaunchpadJSON(w, http.StatusCreated, map[string]any{
		"binding": map[string]any{
			"name":       binding.Name,
			"provider":   binding.Provider,
			"value_env":  binding.ValueEnv,
			"created_at": binding.CreatedAt,
			"updated_at": binding.UpdatedAt,
		},
		"secrets": readmodel.SecretGrantStatuses(statuses),
	})
}

func handleLaunchpadRunPath(w http.ResponseWriter, r *http.Request, rest string, store *launchsession.Store) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		api.WriteBadRequest(w, "launch id required")
		return
	}
	launchID := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		run, err := store.Get(launchID)
		if err != nil {
			api.WriteError(w, http.StatusNotFound, "Launch not found", err.Error())
			return
		}
		writeLaunchpadJSON(w, http.StatusOK, run)
		return
	}
	if len(parts) == 2 && parts[1] == "repair" && r.Method == http.MethodPost {
		run, err := store.Get(launchID)
		if err != nil {
			api.WriteError(w, http.StatusNotFound, "Launch not found", err.Error())
			return
		}
		diagnostics := []repair.Diagnostic{{Code: "ERR_REPAIR_REQUIRES_OPERATOR_APPROVAL", Message: "repair is deterministic planning only until operator approval is recorded"}}
		if run.State == launchsession.StateEscalated {
			diagnostics = append(diagnostics, repair.Diagnostic{Code: "ERR_LAUNCH_ESCALATED", Message: run.Reason})
		}
		writeLaunchpadJSON(w, http.StatusAccepted, repair.EscalatedPlan(launchID, diagnostics))
		return
	}
	if len(parts) == 2 && parts[1] == "delete" && r.Method == http.MethodPost {
		if _, err := store.Get(launchID); err != nil {
			api.WriteError(w, http.StatusNotFound, "Launch not found", err.Error())
			return
		}
		deleted, err := launchsession.NewExecutor(store).DeleteLaunch(launchID, true)
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		writeLaunchpadJSON(w, http.StatusAccepted, deleted)
		return
	}
	api.WriteMethodNotAllowed(w)
}

func decodeLaunchpadPlanRequest(w http.ResponseWriter, r *http.Request) (launchpadPlanRequest, bool) {
	var req launchpadPlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteBadRequest(w, "invalid launchpad request")
		return req, false
	}
	if strings.TrimSpace(req.AppID) == "" || strings.TrimSpace(req.SubstrateID) == "" {
		api.WriteBadRequest(w, "app_id and substrate_id are required")
		return req, false
	}
	if req.Principal == "" {
		req.Principal = "console"
	}
	return req, true
}

func compileLaunchpadPlan(catalog *registry.Catalog, req launchpadPlanRequest, store *launchsession.Store) (plan.LaunchPlan, error) {
	app, ok := catalog.App(req.AppID)
	if !ok {
		return plan.FailurePlan(req.AppID, req.SubstrateID, req.Principal, "DENY", "DENIED", "ERR_LAUNCHPAD_UNKNOWN_APP"), fmt.Errorf("unknown app: %s", req.AppID)
	}
	substrate, ok := catalog.Substrate(req.SubstrateID)
	if !ok {
		return plan.FailurePlan(req.AppID, req.SubstrateID, req.Principal, "DENY", "DENIED", "ERR_LAUNCHPAD_UNKNOWN_SUBSTRATE"), fmt.Errorf("unknown substrate: %s", req.SubstrateID)
	}
	secretRoot := ""
	if store != nil {
		secretRoot = store.Root()
	}
	if _, err := lpsecrets.NewStore(secretRoot).ApplyAppEnv(app); err != nil {
		return plan.FailurePlan(req.AppID, req.SubstrateID, req.Principal, "ESCALATE", "ESCALATED", "ERR_LAUNCHPAD_SECRET_BINDING_INVALID"), err
	}
	return plan.CompileWithRoot(app, substrate, req.Principal, catalog.Root)
}

func detailForStoredRun(catalog *registry.Catalog, run launchsession.LaunchRun) any {
	app, appOK := catalog.App(run.AppID)
	substrate, substrateOK := catalog.Substrate(run.SubstrateID)
	compiled := plan.LaunchPlan{
		LaunchID:           run.LaunchID,
		AppID:              run.AppID,
		AppVersion:         run.AppVersion,
		SubstrateID:        run.SubstrateID,
		Principal:          run.Principal,
		ArtifactImage:      run.ArtifactImage,
		ArtifactDigest:     run.ArtifactDigest,
		PolicyHash:         run.PlanHash,
		SandboxProfileHash: firstNonEmpty(firstString(run.SandboxGrantRefs), run.PlanHash),
		MCPPolicy:          registry.MCPPolicy{UnknownServerPolicy: "quarantine", UnknownToolPolicy: "ESCALATE", RequireSchemaPin: true},
		KernelVerdict:      run.KernelVerdict,
		Status:             string(run.State),
		ReasonCode:         run.ReasonCode,
		PlanHash:           run.PlanHash,
	}
	if appOK && substrateOK {
		return readmodel.Detail(app, substrate, compiled, run)
	}
	return map[string]any{"run": run, "instance": readmodel.RuntimeFromRun(run), "events": readmodel.EventsFromRun(run)}
}

func attachAppEntitlements(w http.ResponseWriter, r *http.Request, apps []readmodel.RegistryApp, catalog *registry.Catalog, store *launchsession.Store) bool {
	client := account.NewClientFromEnv()
	if !client.Enabled() {
		return true
	}
	substrateID := defaultLaunchpadSubstrate(catalog)
	for i := range apps {
		decision, ok := launchpadDecision(w, r, client, "launch", apps[i].AppID, substrateID, "", store)
		if !ok {
			return false
		}
		applyEntitlementFields(&apps[i].UserState, &apps[i].RequiredCapability, &apps[i].UpgradeReason, &apps[i].EntitlementDecision, &apps[i].ActionStates, "launch", decision)
	}
	return true
}

func attachMatrixEntitlements(w http.ResponseWriter, r *http.Request, matrix []registry.MatrixCell, store *launchsession.Store) bool {
	client := account.NewClientFromEnv()
	if !client.Enabled() {
		return true
	}
	for i := range matrix {
		decision, ok := launchpadDecision(w, r, client, "launch", matrix[i].AppID, matrix[i].SubstrateID, "", store)
		if !ok {
			return false
		}
		applyEntitlementFields(&matrix[i].UserState, &matrix[i].RequiredCapability, &matrix[i].UpgradeReason, &matrix[i].EntitlementDecision, &matrix[i].ActionStates, "launch", decision)
		if decision != nil && !decision.Allowed {
			matrix[i].Launchable = false
		}
	}
	return true
}

func attachPlanEntitlements(w http.ResponseWriter, r *http.Request, compiled *plan.LaunchPlan, req launchpadPlanRequest, store *launchsession.Store) bool {
	client := account.NewClientFromEnv()
	if !client.Enabled() {
		return true
	}
	decision, ok := launchpadDecision(w, r, client, "launch", req.AppID, req.SubstrateID, "", store)
	if !ok {
		return false
	}
	applyEntitlementFields(&compiled.UserState, &compiled.RequiredCapability, &compiled.UpgradeReason, &compiled.EntitlementDecision, &compiled.ActionStates, "launch", decision)
	return true
}

func requireLaunchpadEntitlement(w http.ResponseWriter, r *http.Request, action, appID, substrateID, runID string, store *launchsession.Store) bool {
	client := account.NewClientFromEnv()
	if !client.Enabled() {
		return true
	}
	decision, ok := launchpadDecision(w, r, client, action, appID, substrateID, runID, store)
	if !ok {
		return false
	}
	if decision != nil && !decision.Allowed {
		writeLaunchpadJSON(w, http.StatusForbidden, map[string]any{
			"error":                "entitlement_denied",
			"reason":               decision.Reason,
			"upgrade_reason":       decision.UpgradeReason,
			"entitlement_decision": decision,
		})
		return false
	}
	return true
}

func launchpadDecision(w http.ResponseWriter, r *http.Request, client *account.Client, action, appID, substrateID, runID string, store *launchsession.Store) (*account.Decision, bool) {
	principalID, tenantID := launchpadPrincipalTenant(r)
	decision, err := client.Decide(r.Context(), r, account.DecisionRequest{
		PrincipalID:  principalID,
		TenantID:     tenantID,
		Action:       action,
		AppID:        appID,
		SubstrateID:  substrateID,
		CurrentUsage: launchpadUsageCounters(store),
		RunID:        runID,
	})
	if err != nil {
		if client.Required {
			writeLaunchpadJSON(w, http.StatusForbidden, map[string]any{
				"error":  "entitlement_unavailable",
				"reason": err.Error(),
			})
			return nil, false
		}
		return nil, true
	}
	return decision, true
}

func applyEntitlementFields(userState, requiredCapability, upgradeReason *string, entitlementDecision *any, actionStates *map[string]any, action string, decision *account.Decision) {
	if decision == nil {
		return
	}
	*userState = decision.UserState
	*requiredCapability = decision.RequiredCapability
	*upgradeReason = decision.UpgradeReason
	*entitlementDecision = decision
	if *actionStates == nil {
		*actionStates = map[string]any{}
	}
	(*actionStates)[action] = decision
}

func launchpadUsageCounters(store *launchsession.Store) account.UsageCounters {
	var counters account.UsageCounters
	if store == nil {
		return counters
	}
	runs, err := store.List()
	if err != nil {
		return counters
	}
	cloudTargets := map[string]bool{}
	for _, run := range runs {
		if run.State != launchsession.StateDeleted {
			counters.MonthlyLaunches++
		}
		if run.State == launchsession.StateRunning {
			counters.ConcurrentRuns++
		}
		if launchpadSubstrateLooksCloud(run.SubstrateID) {
			cloudTargets[run.SubstrateID] = true
		}
	}
	counters.CloudTargets = int64(len(cloudTargets))
	return counters
}

func launchpadPrincipalTenant(r *http.Request) (string, string) {
	if principal, err := helmauth.GetPrincipal(r.Context()); err == nil && principal != nil {
		return principal.GetID(), principal.GetTenantID()
	}
	return strings.TrimSpace(r.Header.Get(principalHeader)), strings.TrimSpace(r.Header.Get(tenantHeader))
}

func defaultLaunchpadSubstrate(catalog *registry.Catalog) string {
	if catalog == nil {
		return "local-container"
	}
	for _, substrate := range catalog.Substrates {
		if substrate.ID == "local-container" {
			return substrate.ID
		}
	}
	if len(catalog.Substrates) > 0 {
		return catalog.Substrates[0].ID
	}
	return "local-container"
}

func launchpadSubstrateLooksCloud(substrateID string) bool {
	value := strings.ToLower(strings.TrimSpace(substrateID))
	return strings.Contains(value, "cloud") ||
		strings.Contains(value, "aws") ||
		strings.Contains(value, "gcp") ||
		strings.Contains(value, "azure") ||
		strings.Contains(value, "e2b") ||
		strings.Contains(value, "daytona") ||
		strings.Contains(value, "hetzner") ||
		strings.Contains(value, "digitalocean")
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func lastString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

func proofStatusForRefs(refs []string) string {
	for _, ref := range refs {
		if strings.TrimSpace(ref) != "" {
			return "proven"
		}
	}
	return "unproven"
}

func sanitizeReceiptPart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "unknown"
	}
	return out
}

func shellQuote(value string) string {
	if value == "" {
		return `""`
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func writeLaunchpadJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
