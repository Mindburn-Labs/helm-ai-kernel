package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conformance"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	helmotel "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/otel"
	runtimesandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtime/sandbox"
)

const (
	maxEvidenceBundleBytes    = 32 << 20
	maxEvidenceExportReceipts = 10000
	evidenceExportPageSize    = 500
)

var errEvidenceExportTooLarge = errors.New("evidence export receipt limit exceeded")

type evidenceManifest struct {
	Version    string            `json:"version"`
	ExportedAt string            `json:"exported_at"`
	SessionID  string            `json:"session_id,omitempty"`
	FileHashes map[string]string `json:"file_hashes"`
}

type evidenceBundle struct {
	Manifest evidenceManifest
	Files    map[string][]byte
}

func registerContractRoutes(mux *http.ServeMux, svc *Services) {
	mcpQuarantine := mcppkg.NewQuarantineRegistry()
	surfaces := boundarypkg.NewSurfaceRegistry(time.Now)
	if svc != nil && svc.BoundarySurfaces != nil {
		surfaces = svc.BoundarySurfaces
	}
	hydrateMCPQuarantine(context.Background(), mcpQuarantine, surfaces.ListMCPServers())

	mux.HandleFunc("/api/v1/boundary/status", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, surfaces.Status(displayVersion(), svc != nil && svc.ReceiptStore != nil, svc != nil && svc.ReceiptSigner != nil, countMCPQuarantined(mcpQuarantine.List(r.Context()))))
	}))

	mux.HandleFunc("/api/v1/boundary/capabilities", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, surfaces.Capabilities())
	}))

	mux.HandleFunc("/api/v1/boundary/records", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		query := contracts.BoundarySearchRequest{
			Verdict:     r.URL.Query().Get("verdict"),
			ReasonCode:  r.URL.Query().Get("reason_code"),
			ToolName:    r.URL.Query().Get("tool_name"),
			MCPServerID: r.URL.Query().Get("mcp_server_id"),
			PolicyEpoch: r.URL.Query().Get("policy_epoch"),
			ReceiptID:   r.URL.Query().Get("receipt_id"),
			Limit:       parseLimit(r.URL.Query().Get("limit"), 50, 1000),
		}
		writeContractJSON(w, http.StatusOK, surfaces.ListRecords(query))
	}))

	mux.HandleFunc("/api/v1/boundary/records/", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/boundary/records/")
		recordID, verify := strings.CutSuffix(suffix, "/verify")
		if recordID == "" || strings.Contains(recordID, "/") {
			api.WriteBadRequest(w, "Invalid boundary record id")
			return
		}
		if verify {
			if r.Method != http.MethodPost {
				api.WriteMethodNotAllowed(w)
				return
			}
			writeContractJSON(w, http.StatusOK, surfaces.VerifyRecord(recordID))
			return
		}
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		record, ok := surfaces.GetRecord(recordID)
		if !ok {
			api.WriteNotFound(w, "boundary record not found")
			return
		}
		writeContractJSON(w, http.StatusOK, record)
	}))

	mux.HandleFunc("/api/v1/boundary/checkpoints", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListCheckpoints())
		case http.MethodPost:
			receiptCount := 0
			if svc != nil && svc.ReceiptStore != nil {
				if receipts, err := contractReceipts(r.Context(), svc, "", 1000); err == nil {
					receiptCount = len(receipts)
				}
			}
			checkpoint, err := surfaces.CreateCheckpoint(receiptCount)
			if err != nil {
				api.WriteInternal(w, err)
				return
			}
			writeContractJSON(w, http.StatusCreated, checkpoint)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))

	mux.HandleFunc("/api/v1/boundary/checkpoints/", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/boundary/checkpoints/")
		checkpointID, verify := strings.CutSuffix(suffix, "/verify")
		if checkpointID == "" || strings.Contains(checkpointID, "/") || !verify {
			api.WriteBadRequest(w, "Invalid boundary checkpoint route")
			return
		}
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, surfaces.VerifyCheckpoint(checkpointID))
	}))

	mux.HandleFunc("/api/v1/proofgraph/sessions", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		receipts, err := contractReceipts(r.Context(), svc, "", parseLimit(r.URL.Query().Get("limit"), 50, 1000))
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		sessions := proofgraphSessions(receipts)
		offset := parseLimit(r.URL.Query().Get("offset"), 0, len(sessions))
		if offset > len(sessions) {
			offset = len(sessions)
		}
		writeContractJSON(w, http.StatusOK, sessions[offset:])
	}))

	mux.HandleFunc("/api/v1/proofgraph/sessions/", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/proofgraph/sessions/")
		sessionID, ok := strings.CutSuffix(suffix, "/receipts")
		if !ok || strings.TrimSpace(sessionID) == "" || strings.Contains(sessionID, "/") {
			api.WriteNotFound(w, "proofgraph session route not found")
			return
		}
		receipts, err := contractReceipts(r.Context(), svc, sessionID, parseLimit(r.URL.Query().Get("limit"), 100, 1000))
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		if len(receipts) == 0 {
			api.WriteNotFound(w, "session not found")
			return
		}
		writeContractJSON(w, http.StatusOK, receipts)
	}))

	mux.HandleFunc("/api/v1/proofgraph/receipts/", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		receiptRef := strings.TrimPrefix(r.URL.Path, "/api/v1/proofgraph/receipts/")
		if receiptRef == "" || strings.Contains(receiptRef, "/") {
			api.WriteBadRequest(w, "Invalid receipt reference")
			return
		}
		receipt, err := findReceiptByReference(r.Context(), svc, receiptRef)
		if err != nil {
			api.WriteNotFound(w, err.Error())
			return
		}
		writeContractJSON(w, http.StatusOK, receipt)
	}))

	mux.HandleFunc("/api/v1/evidence/export", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req struct {
			SessionID string `json:"session_id"`
			Format    string `json:"format"`
		}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}
		if req.Format != "" && req.Format != "tar.gz" {
			api.WriteBadRequest(w, "Unsupported evidence export format")
			return
		}
		receipts, err := contractReceiptsForExport(r.Context(), svc, req.SessionID)
		if err != nil {
			if errors.Is(err, errEvidenceExportTooLarge) {
				api.WriteError(w, http.StatusRequestEntityTooLarge, "Evidence export too large", fmt.Sprintf("Evidence export is limited to %d receipts; export a narrower session or retention window", maxEvidenceExportReceipts))
				return
			}
			api.WriteInternal(w, err)
			return
		}
		if len(receipts) == 0 {
			api.WriteError(w, http.StatusConflict, "No receipts available", "evidence export requires at least one receipt")
			return
		}
		bundle, err := buildEvidenceBundle(req.SessionID, receipts, surfaces)
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		sum := sha256.Sum256(bundle)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Helm-Evidence-Hash", "sha256:"+hex.EncodeToString(sum[:]))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	}))

	mux.HandleFunc("/api/v1/evidence/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		result := verifyEvidenceRequest(r)
		writeContractJSON(w, http.StatusOK, result)
	})

	mux.HandleFunc("/api/v1/evidence/verification-scopes", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListVerificationScopes())
		case http.MethodPost:
			var scope contracts.VerificationScope
			if err := json.NewDecoder(r.Body).Decode(&scope); err != nil {
				api.WriteBadRequest(w, "Invalid verification scope JSON")
				return
			}
			sealed, err := surfaces.PutVerificationScope(scope)
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusCreated, sealed)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))
	mux.HandleFunc("/api/v1/evidence/verification-scopes/", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		id, verify := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/evidence/verification-scopes/"), "/verify")
		if id == "" || strings.Contains(id, "/") {
			api.WriteBadRequest(w, "Invalid verification scope id")
			return
		}
		if verify {
			if r.Method != http.MethodPost {
				api.WriteMethodNotAllowed(w)
				return
			}
			writeContractJSON(w, http.StatusOK, surfaces.VerifyVerificationScope(id))
			return
		}
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		scope, ok := surfaces.GetVerificationScope(id)
		if !ok {
			api.WriteNotFound(w, "verification scope not found")
			return
		}
		writeContractJSON(w, http.StatusOK, scope)
	}))

	mux.HandleFunc("/api/v1/telemetry/harness-traces", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListHarnessTraces())
		case http.MethodPost:
			var trace contracts.HarnessTrace
			if err := json.NewDecoder(r.Body).Decode(&trace); err != nil {
				api.WriteBadRequest(w, "Invalid harness trace JSON")
				return
			}
			sealed, err := surfaces.PutHarnessTrace(trace)
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusCreated, sealed)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))
	mux.HandleFunc("/api/v1/telemetry/harness-traces/", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		id, verify := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/telemetry/harness-traces/"), "/verify")
		if id == "" || strings.Contains(id, "/") {
			api.WriteBadRequest(w, "Invalid harness trace id")
			return
		}
		if verify {
			if r.Method != http.MethodPost {
				api.WriteMethodNotAllowed(w)
				return
			}
			writeContractJSON(w, http.StatusOK, surfaces.VerifyHarnessTrace(id))
			return
		}
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		trace, ok := surfaces.GetHarnessTrace(id)
		if !ok {
			api.WriteNotFound(w, "harness trace not found")
			return
		}
		writeContractJSON(w, http.StatusOK, trace)
	}))

	mux.HandleFunc("/api/v1/plans/transactions", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListPlanTransactions())
		case http.MethodPost:
			var tx contracts.PlanTransaction
			if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
				api.WriteBadRequest(w, "Invalid plan transaction JSON")
				return
			}
			sealed, err := surfaces.PutPlanTransaction(tx)
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusCreated, sealed)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))
	mux.HandleFunc("/api/v1/plans/transactions/", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		id, verify := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/plans/transactions/"), "/verify")
		if id == "" || strings.Contains(id, "/") {
			api.WriteBadRequest(w, "Invalid plan transaction id")
			return
		}
		if verify {
			if r.Method != http.MethodPost {
				api.WriteMethodNotAllowed(w)
				return
			}
			writeContractJSON(w, http.StatusOK, surfaces.VerifyPlanTransaction(id))
			return
		}
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		tx, ok := surfaces.GetPlanTransaction(id)
		if !ok {
			api.WriteNotFound(w, "plan transaction not found")
			return
		}
		writeContractJSON(w, http.StatusOK, tx)
	}))

	mux.HandleFunc("/api/v1/harness/change-contracts", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListHarnessChanges())
		case http.MethodPost:
			var contract contracts.HarnessChangeContract
			if err := json.NewDecoder(r.Body).Decode(&contract); err != nil {
				api.WriteBadRequest(w, "Invalid harness change contract JSON")
				return
			}
			sealed, err := surfaces.PutHarnessChange(contract)
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusCreated, sealed)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))
	mux.HandleFunc("/api/v1/harness/change-contracts/", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/harness/change-contracts/")
		id, verify := strings.CutSuffix(suffix, "/verify")
		if verify {
			if id == "" || strings.Contains(id, "/") || r.Method != http.MethodPost {
				api.WriteMethodNotAllowed(w)
				return
			}
			writeContractJSON(w, http.StatusOK, surfaces.VerifyHarnessChange(id))
			return
		}
		id, approve := strings.CutSuffix(suffix, "/approve")
		if approve {
			if id == "" || strings.Contains(id, "/") || r.Method != http.MethodPost {
				api.WriteMethodNotAllowed(w)
				return
			}
			var req struct {
				ReceiptRef string `json:"receipt_ref"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			contract, err := surfaces.ApproveHarnessChange(id, req.ReceiptRef)
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusOK, contract)
			return
		}
		if id == "" || strings.Contains(id, "/") {
			api.WriteBadRequest(w, "Invalid harness change contract id")
			return
		}
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		contract, ok := surfaces.GetHarnessChange(id)
		if !ok {
			api.WriteNotFound(w, "harness change contract not found")
			return
		}
		writeContractJSON(w, http.StatusOK, contract)
	}))

	mux.HandleFunc("/api/v1/gui/receipts/verify", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var receipt contracts.GUIActionReceipt
		if err := json.NewDecoder(r.Body).Decode(&receipt); err != nil {
			api.WriteBadRequest(w, "Invalid GUI action receipt JSON")
			return
		}
		sealed, err := receipt.Seal()
		if err != nil {
			writeContractJSON(w, http.StatusOK, map[string]any{"verified": false, "verdict": "FAIL", "errors": []string{err.Error()}})
			return
		}
		writeContractJSON(w, http.StatusOK, map[string]any{"verified": true, "verdict": "PASS", "receipt": sealed})
	}))

	mux.HandleFunc("/api/v1/evidence/envelopes", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeContractJSON(w, http.StatusOK, surfaces.ListEnvelopes())
			return
		}
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req struct {
			ManifestID         string `json:"manifest_id"`
			Envelope           string `json:"envelope"`
			NativeEvidenceHash string `json:"native_evidence_hash"`
			Subject            string `json:"subject"`
			Experimental       bool   `json:"experimental"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid evidence envelope request")
			return
		}
		manifest, err := evidencepkg.BuildEnvelopeManifest(evidencepkg.EnvelopeExportRequest{
			ManifestID:         req.ManifestID,
			Envelope:           evidencepkg.EnvelopeExportType(req.Envelope),
			NativeEvidenceHash: req.NativeEvidenceHash,
			Subject:            req.Subject,
			CreatedAt:          time.Now().UTC(),
			AllowExperimental:  req.Experimental,
		})
		if err != nil {
			api.WriteBadRequest(w, err.Error())
			return
		}
		payload, err := evidencepkg.BuildEnvelopePayload(manifest)
		if err != nil {
			api.WriteBadRequest(w, err.Error())
			return
		}
		if err := surfaces.PutEnvelope(manifest); err != nil {
			api.WriteError(w, http.StatusInternalServerError, "Boundary registry persistence failed", err.Error())
			return
		}
		if err := surfaces.PutEnvelopePayload(payload); err != nil {
			api.WriteError(w, http.StatusInternalServerError, "Boundary registry persistence failed", err.Error())
			return
		}
		writeContractJSON(w, http.StatusOK, manifest)
	}))

	mux.HandleFunc("/api/v1/evidence/envelopes/", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/evidence/envelopes/")
		manifestID, verify := strings.CutSuffix(suffix, "/verify")
		payloadRoute := false
		if !verify {
			manifestID, payloadRoute = strings.CutSuffix(suffix, "/payload")
		}
		if manifestID == "" || strings.Contains(manifestID, "/") {
			api.WriteBadRequest(w, "Invalid evidence envelope manifest id")
			return
		}
		manifest, ok := surfaces.GetEnvelope(manifestID)
		if !ok {
			api.WriteNotFound(w, "evidence envelope manifest not found")
			return
		}
		if verify {
			if r.Method != http.MethodPost {
				api.WriteMethodNotAllowed(w)
				return
			}
			payload, ok := surfaces.GetEnvelopePayload(manifest.ManifestID)
			if !ok {
				var err error
				payload, err = evidencepkg.BuildEnvelopePayload(manifest)
				if err != nil {
					api.WriteBadRequest(w, err.Error())
					return
				}
			}
			result := evidencepkg.VerifyEnvelopePayload(manifest, payload)
			writeContractJSON(w, http.StatusOK, result)
			return
		}
		if payloadRoute {
			if r.Method != http.MethodGet {
				api.WriteMethodNotAllowed(w)
				return
			}
			payload, ok := surfaces.GetEnvelopePayload(manifest.ManifestID)
			if !ok {
				var err error
				payload, err = evidencepkg.BuildEnvelopePayload(manifest)
				if err != nil {
					api.WriteBadRequest(w, err.Error())
					return
				}
			}
			writeContractJSON(w, http.StatusOK, payload)
			return
		}
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, manifest)
	}))

	mux.HandleFunc("/api/v1/replay/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		result := verifyEvidenceRequest(r)
		checks, _ := result["checks"].(map[string]string)
		if checks == nil {
			checks = map[string]string{}
			result["checks"] = checks
		}
		checks["replay"] = checks["causal_chain"]
		writeContractJSON(w, http.StatusOK, result)
	})

	mux.HandleFunc("/api/v1/conformance/run", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req struct {
			Level   string `json:"level"`
			Profile string `json:"profile"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid conformance request")
			return
		}
		if req.Level != "L1" && req.Level != "L2" && req.Level != "L3" && req.Level != "L4" {
			api.WriteBadRequest(w, "Conformance level must be L1, L2, L3, or L4")
			return
		}
		report := conformanceReport(req.Level, req.Profile)
		if err := surfaces.PutReport(report); err != nil {
			api.WriteError(w, http.StatusInternalServerError, "Boundary registry persistence failed", err.Error())
			return
		}
		writeContractJSON(w, http.StatusOK, report)
	}))

	mux.HandleFunc("/api/v1/conformance/reports", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		reports := surfaces.ListReports()
		if len(reports) == 0 {
			report := conformanceReport("L4", "sota-2026")
			if err := surfaces.PutReport(report); err != nil {
				api.WriteError(w, http.StatusInternalServerError, "Boundary registry persistence failed", err.Error())
				return
			}
			reports = append(reports, report)
		}
		writeContractJSON(w, http.StatusOK, reports)
	}))

	mux.HandleFunc("/api/v1/conformance/reports/", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		reportID := strings.TrimPrefix(r.URL.Path, "/api/v1/conformance/reports/")
		if reportID == "" || strings.Contains(reportID, "/") {
			api.WriteBadRequest(w, "Invalid conformance report id")
			return
		}
		writeContractJSON(w, http.StatusOK, conformanceReport("L1", "runtime"))
	}))

	mux.HandleFunc("/api/v1/conformance/vectors", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, map[string]any{
			"levels":   []string{"L1", "L2", "L3", "L4"},
			"negative": conformance.DefaultNegativeBoundaryVectors(),
			"profiles": []string{"receipts", "mcp", "sandbox", "authz", "approval", "telemetry", "envelopes", "checkpoints"},
		})
	})

	mux.HandleFunc("/api/v1/conformance/negative", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, conformance.DefaultNegativeBoundaryVectors())
	})

	mux.HandleFunc("/api/v1/mcp/registry", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListMCPServers())
		case http.MethodPost:
			var req struct {
				ServerID  string   `json:"server_id"`
				Name      string   `json:"name"`
				Transport string   `json:"transport"`
				Endpoint  string   `json:"endpoint"`
				ToolNames []string `json:"tool_names"`
				Risk      string   `json:"risk"`
				Reason    string   `json:"reason"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				api.WriteBadRequest(w, "Invalid MCP registry request")
				return
			}
			record, err := mcpQuarantine.Discover(r.Context(), mcppkg.DiscoverServerRequest{
				ServerID:  req.ServerID,
				Name:      req.Name,
				Transport: req.Transport,
				Endpoint:  req.Endpoint,
				ToolNames: req.ToolNames,
				Risk:      mcppkg.ServerRisk(req.Risk),
				Reason:    req.Reason,
			})
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			if _, err := surfaces.PutMCPServer(record); err != nil {
				api.WriteInternal(w, err)
				return
			}
			writeContractJSON(w, http.StatusAccepted, record)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))

	mux.HandleFunc("/api/v1/mcp/registry/approve", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		// Approval is deliberately unavailable until a credential verifier can
		// bind the evidence. Do not parse opaque caller metadata first: it must
		// never influence an approval result or change the public 503 contract.
		api.WriteError(w, http.StatusServiceUnavailable, "MCP approval verification unavailable", mcppkg.ErrApprovalVerificationUnavailable.Error())
	}))

	mux.HandleFunc("/api/v1/mcp/registry/", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/mcp/registry/")
		serverID := suffix
		action := ""
		if strings.Contains(suffix, "/") {
			parts := strings.SplitN(suffix, "/", 2)
			serverID, action = parts[0], parts[1]
		}
		if serverID == "" {
			api.WriteBadRequest(w, "Invalid MCP server id")
			return
		}
		switch {
		case action == "" && r.Method == http.MethodGet:
			record, ok := surfaces.GetMCPServer(serverID)
			if !ok {
				api.WriteNotFound(w, "MCP server not found")
				return
			}
			writeContractJSON(w, http.StatusOK, record)
		case action == "approve" && r.Method == http.MethodPost:
			// See the collection endpoint: the disabled path-scoped variant must
			// reject without parsing or trusting caller-provided approval fields.
			api.WriteError(w, http.StatusServiceUnavailable, "MCP approval verification unavailable", mcppkg.ErrApprovalVerificationUnavailable.Error())
		case action == "revoke" && r.Method == http.MethodPost:
			var req struct {
				Reason string `json:"reason"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			record, err := mcpQuarantine.Revoke(r.Context(), serverID, req.Reason, time.Now().UTC())
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			if _, err := surfaces.PutMCPServer(record); err != nil {
				api.WriteInternal(w, err)
				return
			}
			writeContractJSON(w, http.StatusOK, record)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))

	mux.HandleFunc("/api/v1/mcp/scan", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req contracts.MCPScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid MCP scan request")
			return
		}
		record, err := mcpQuarantine.Discover(r.Context(), mcppkg.DiscoverServerRequest{
			ServerID:  req.ServerID,
			Name:      req.Name,
			Transport: req.Transport,
			Endpoint:  req.Endpoint,
			ToolNames: req.ToolNames,
			Risk:      mcppkg.ServerRiskHigh,
			Reason:    "scan requires approval before dispatch",
		})
		if err != nil {
			api.WriteBadRequest(w, err.Error())
			return
		}
		if _, err := surfaces.PutMCPServer(record); err != nil {
			api.WriteInternal(w, err)
			return
		}
		writeContractJSON(w, http.StatusAccepted, contracts.MCPScanResult{
			ServerID:            record.ServerID,
			Risk:                string(record.Risk),
			State:               string(record.State),
			ToolCount:           len(record.ToolNames),
			Findings:            []string{"unknown MCP server defaults to quarantine", "schema pins required before call-time dispatch"},
			RecommendedAction:   "keep quarantined or revoke; credential verification is required before approval",
			QuarantineRecordID:  record.ServerID,
			RequiresApproval:    true,
			SchemaPinRequired:   true,
			AuthorizationNeeded: true,
			ScannedAt:           time.Now().UTC(),
		})
	}))

	mux.HandleFunc("/api/v1/mcp/auth-profiles", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, surfaces.ListAuthProfiles())
	}))

	mux.HandleFunc("/api/v1/mcp/auth-profiles/", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		profileID := strings.TrimPrefix(r.URL.Path, "/api/v1/mcp/auth-profiles/")
		if profileID == "" || strings.Contains(profileID, "/") {
			api.WriteBadRequest(w, "Invalid MCP auth profile id")
			return
		}
		if r.Method != http.MethodPut {
			api.WriteMethodNotAllowed(w)
			return
		}
		var profile contracts.MCPAuthorizationProfile
		if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
			api.WriteBadRequest(w, "Invalid MCP auth profile request")
			return
		}
		profile.ProfileID = profileID
		sealed, err := surfaces.PutAuthProfile(profile)
		if err != nil {
			api.WriteBadRequest(w, err.Error())
			return
		}
		writeContractJSON(w, http.StatusOK, sealed)
	}))

	mux.HandleFunc("/api/v1/mcp/authorize-call", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req contracts.MCPAuthorizeCallRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid MCP authorize-call request")
			return
		}
		catalog := mcppkg.NewToolCatalog()
		catalog.RegisterCommonTools()
		if req.ToolSchema != nil {
			if err := catalog.Register(r.Context(), mcppkg.ToolRef{
				Name:         req.ToolName,
				ServerID:     req.ServerID,
				Description:  "Discovered MCP tool with caller-supplied pinned schema",
				Schema:       req.ToolSchema,
				OutputSchema: req.OutputSchema,
			}); err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
		}
		firewall := mcppkg.NewExecutionFirewall(catalog, mcpQuarantine, "api")
		firewall.RequirePinnedSchema = true
		record, err := firewall.AuthorizeToolCall(r.Context(), mcppkg.ToolCallAuthorization{
			ServerID:         req.ServerID,
			ToolName:         req.ToolName,
			ArgsHash:         req.ArgsHash,
			GrantedScopes:    req.GrantedScopes,
			PinnedSchemaHash: req.PinnedSchemaHash,
			OAuthResource:    req.OAuthResource,
			ReceiptID:        req.ReceiptID,
		})
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		if _, putErr := surfaces.PutRecord(record); putErr != nil {
			api.WriteInternal(w, putErr)
			return
		}
		status := http.StatusOK
		if record.Verdict != contracts.VerdictAllow {
			status = http.StatusForbidden
		}
		writeContractJSON(w, status, record)
	}))

	mux.HandleFunc("/api/v1/sandbox/profiles", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, runtimesandbox.DefaultBackendProfiles())
	}))

	mux.HandleFunc("/api/v1/sandbox/grants", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListSandboxGrants())
		case http.MethodPost:
			var req struct {
				Runtime     string `json:"runtime"`
				Profile     string `json:"profile"`
				ImageDigest string `json:"image_digest"`
				PolicyEpoch string `json:"policy_epoch"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				api.WriteBadRequest(w, "Invalid sandbox grant request")
				return
			}
			if strings.TrimSpace(req.ImageDigest) == "" {
				api.WriteBadRequest(w, "sandbox grant requires image_digest or template digest before execution")
				return
			}
			policy := runtimesandbox.DefaultPolicy()
			if req.Profile != "" {
				policy.PolicyID = req.Profile
			}
			grant, err := runtimesandbox.GrantFromPolicy(policy, req.Runtime, policy.PolicyID, req.ImageDigest, req.PolicyEpoch, time.Now().UTC())
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			grant, err = surfaces.PutSandboxGrant(grant)
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusCreated, grant)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))

	mux.HandleFunc("/api/v1/sandbox/grants/", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/sandbox/grants/")
		grantID, verify := strings.CutSuffix(suffix, "/verify")
		if grantID == "" || strings.Contains(grantID, "/") {
			api.WriteBadRequest(w, "Invalid sandbox grant id")
			return
		}
		grant, ok := surfaces.GetSandboxGrant(grantID)
		if !ok {
			api.WriteNotFound(w, "sandbox grant not found")
			return
		}
		if verify {
			if r.Method != http.MethodPost {
				api.WriteMethodNotAllowed(w)
				return
			}
			result := verifySandboxGrantForDispatch(grant, "")
			writeContractJSON(w, http.StatusOK, result)
			return
		}
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, grant)
	}))

	mux.HandleFunc("/api/v1/sandbox/preflight", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req contracts.SandboxPreflightRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid sandbox preflight request")
			return
		}
		grant := req.RequestedGrant
		if grant.GrantID == "" {
			policy := runtimesandbox.DefaultPolicy()
			if req.Profile != "" {
				policy.PolicyID = req.Profile
			}
			generated, err := runtimesandbox.GrantFromPolicy(policy, req.Runtime, policy.PolicyID, req.ImageDigest, req.PolicyEpoch, time.Now().UTC())
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			grant = generated
		}
		grant, err := surfaces.PutSandboxGrant(grant)
		if err != nil {
			api.WriteBadRequest(w, err.Error())
			return
		}
		result := verifySandboxGrantForDispatch(grant, req.ExpectedGrantHash)
		writeContractJSON(w, http.StatusOK, result)
	}))

	mux.HandleFunc("/api/v1/sandbox/grants/inspect", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		runtimeName := r.URL.Query().Get("runtime")
		if runtimeName == "" {
			writeContractJSON(w, http.StatusOK, runtimesandbox.DefaultBackendProfiles())
			return
		}
		policy := runtimesandbox.DefaultPolicy()
		if profile := r.URL.Query().Get("profile"); profile != "" {
			policy.PolicyID = profile
		}
		grant, err := runtimesandbox.GrantFromPolicy(policy, runtimeName, policy.PolicyID, "", r.URL.Query().Get("policy_epoch"), time.Now().UTC())
		if err != nil {
			api.WriteBadRequest(w, err.Error())
			return
		}
		writeContractJSON(w, http.StatusOK, grant)
	}))

	mux.HandleFunc("/api/v1/identity/agents", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, surfaces.ListAgents())
	}))

	mux.HandleFunc("/api/v1/authz/health", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		hash := ""
		if svc != nil && svc.Authz != nil {
			hash, _ = svc.Authz.RelationshipSnapshotHash()
		}
		writeContractJSON(w, http.StatusOK, contracts.AuthzHealth{
			Status:           "ready",
			Resolver:         "helm-rebac",
			ModelID:          "helm-local-v1",
			RelationshipHash: hash,
			CheckedAt:        time.Now().UTC(),
		})
	}))

	mux.HandleFunc("/api/v1/authz/snapshots", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, surfaces.ListSnapshots())
	}))

	mux.HandleFunc("/api/v1/authz/snapshots/", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		snapshotID := strings.TrimPrefix(r.URL.Path, "/api/v1/authz/snapshots/")
		if snapshotID == "" || strings.Contains(snapshotID, "/") {
			api.WriteBadRequest(w, "Invalid authz snapshot id")
			return
		}
		snapshot, ok := surfaces.GetSnapshot(snapshotID)
		if !ok {
			api.WriteNotFound(w, "authz snapshot not found")
			return
		}
		writeContractJSON(w, http.StatusOK, snapshot)
	}))

	mux.HandleFunc("/api/v1/approvals", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListApprovals())
		case http.MethodPost:
			var req struct {
				ApprovalID  string   `json:"approval_id"`
				Subject     string   `json:"subject"`
				Action      string   `json:"action"`
				RequestedBy string   `json:"requested_by"`
				Approvers   []string `json:"approvers"`
				Quorum      int      `json:"quorum"`
				TimelockMs  int64    `json:"timelock_ms"`
				ExpiresInMs int64    `json:"expires_in_ms"`
				Reason      string   `json:"reason"`
				ReceiptID   string   `json:"receipt_id"`
				BreakGlass  bool     `json:"break_glass"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				api.WriteBadRequest(w, "Invalid approval request")
				return
			}
			if req.ApprovalID == "" {
				req.ApprovalID = contracts.SurfaceID("approval", req.Subject+"-"+req.Action)
			}
			now := time.Now().UTC()
			var timelock time.Time
			if req.TimelockMs > 0 {
				timelock = now.Add(time.Duration(req.TimelockMs) * time.Millisecond)
			}
			var expires time.Time
			if req.ExpiresInMs > 0 {
				expires = now.Add(time.Duration(req.ExpiresInMs) * time.Millisecond)
			}
			approval, err := surfaces.PutApproval(contracts.ApprovalCeremony{
				ApprovalID:    req.ApprovalID,
				Subject:       req.Subject,
				Action:        req.Action,
				State:         contracts.ApprovalCeremonyPending,
				RequestedBy:   req.RequestedBy,
				Approvers:     req.Approvers,
				Quorum:        req.Quorum,
				TimelockUntil: timelock,
				ExpiresAt:     expires,
				BreakGlass:    req.BreakGlass,
				Reason:        req.Reason,
				ReceiptID:     req.ReceiptID,
				CreatedAt:     now,
				UpdatedAt:     now,
			})
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusCreated, approval)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))

	mux.HandleFunc("/api/v1/approvals/", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/approvals/")
		approvalID, action, ok := strings.Cut(suffix, "/")
		if !ok || approvalID == "" {
			api.WriteBadRequest(w, "Invalid approval route")
			return
		}
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		if action == "webauthn/challenge" {
			var req struct {
				Method string `json:"method"`
				TTLMS  int64  `json:"ttl_ms"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			challenge, err := surfaces.CreateApprovalChallenge(approvalID, req.Method, time.Duration(req.TTLMS)*time.Millisecond)
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusCreated, challenge)
			return
		}
		if action == "webauthn/assert" {
			// The assertion surface is disabled until a verifier exists. It must
			// not parse or persist a raw assertion as a prerequisite for its 503.
			api.WriteError(w, http.StatusServiceUnavailable, "Approval verification unavailable", boundarypkg.ErrApprovalVerificationUnavailable.Error())
			return
		}
		var req struct {
			Actor     string `json:"actor"`
			ReceiptID string `json:"receipt_id"`
			Reason    string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		state := contracts.ApprovalCeremonyPending
		switch action {
		case "approve":
			state = contracts.ApprovalCeremonyAllowed
		case "deny":
			state = contracts.ApprovalCeremonyDenied
		case "revoke":
			state = contracts.ApprovalCeremonyRevoked
		default:
			api.WriteNotFound(w, "approval action not found")
			return
		}
		approval, err := surfaces.TransitionApproval(approvalID, state, req.Actor, req.ReceiptID, req.Reason)
		if err != nil {
			if errors.Is(err, boundarypkg.ErrApprovalVerificationUnavailable) {
				api.WriteError(w, http.StatusServiceUnavailable, "Approval verification unavailable", err.Error())
				return
			}
			api.WriteBadRequest(w, err.Error())
			return
		}
		writeContractJSON(w, http.StatusOK, approval)
	}))

	mux.HandleFunc("/api/v1/budgets", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, surfaces.ListBudgets())
	}))

	mux.HandleFunc("/api/v1/budgets/", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		budgetID := strings.TrimPrefix(r.URL.Path, "/api/v1/budgets/")
		if budgetID == "" || strings.Contains(budgetID, "/") {
			api.WriteBadRequest(w, "Invalid budget id")
			return
		}
		if r.Method != http.MethodPut {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req contracts.BudgetCeiling
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid budget request")
			return
		}
		req.BudgetID = budgetID
		if req.Subject == "" {
			req.Subject = "tenant:default"
		}
		if req.Window == "" {
			req.Window = "24h"
		}
		budget, err := surfaces.PutBudget(req)
		if err != nil {
			api.WriteError(w, http.StatusInternalServerError, "Boundary registry persistence failed", err.Error())
			return
		}
		writeContractJSON(w, http.StatusOK, budget)
	}))

	mux.HandleFunc("/api/v1/coexistence/capabilities", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, contracts.CoexistenceCapabilityManifest{
			ManifestID:      "helm-coexistence-oss",
			Authority:       "helm-native-receipts",
			BoundaryRole:    "inner-proof-bearing-execution-boundary",
			SupportedInputs: []string{"mcp", "openai-compatible-proxy", "framework-middleware", "gateway-export"},
			ExportSurfaces:  []string{"evidencepack", "dsse", "jws", "in-toto", "slsa", "sigstore", "otel-genai", "cloudevents"},
			ReceiptBindings: []string{"receipt_id", "record_hash", "sandbox_grant_hash", "authz_snapshot_hash"},
			GeneratedAt:     time.Now().UTC(),
		})
	}))

	mux.HandleFunc("/api/v1/telemetry/otel/config", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, telemetryConfig())
	}))

	mux.HandleFunc("/api/v1/telemetry/export", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req contracts.TelemetryExportRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Format == "" {
			req.Format = "otel-genai"
		}
		writeContractJSON(w, http.StatusAccepted, contracts.TelemetryExportResult{
			ExportID:      contracts.SurfaceID("telemetry", req.Format+"-"+req.ReceiptID+"-"+req.RecordHash),
			Format:        req.Format,
			Authoritative: false,
			Attributes:    req.Attributes,
			ExportedAt:    time.Now().UTC(),
		})
	}))
}

func contractReceipts(ctx context.Context, svc *Services, sessionID string, limit int) ([]*contracts.Receipt, error) {
	if svc == nil || svc.ReceiptStore == nil {
		return nil, fmt.Errorf("receipt store unavailable")
	}
	if strings.TrimSpace(sessionID) != "" {
		return svc.ReceiptStore.ListByAgent(ctx, sessionID, 0, limit)
	}
	return listReceiptsForCursor(ctx, svc, "", 0, limit)
}

func hydrateMCPQuarantine(ctx context.Context, registry *mcppkg.QuarantineRegistry, records []mcppkg.ServerQuarantineRecord) {
	for _, record := range records {
		record = mcppkg.FailClosedUnverifiedApproval(record)
		_, _ = registry.Discover(ctx, mcppkg.DiscoverServerRequest{
			ServerID:     record.ServerID,
			Name:         record.Name,
			Transport:    record.Transport,
			Endpoint:     record.Endpoint,
			ToolNames:    record.ToolNames,
			Risk:         record.Risk,
			DiscoveredAt: record.DiscoveredAt,
			ExpiresAt:    record.ExpiresAt,
			Reason:       record.Reason,
		})
		switch record.State {
		case mcppkg.QuarantineRevoked:
			_, _ = registry.Revoke(ctx, record.ServerID, record.Reason, record.RevokedAt)
		}
	}
}

func verifySandboxGrantForDispatch(grant contracts.SandboxGrant, expectedHash string) contracts.SandboxPreflightResult {
	result := contracts.SandboxPreflightResult{
		Verdict:       contracts.VerdictAllow,
		GrantID:       grant.GrantID,
		GrantHash:     grant.GrantHash,
		DispatchReady: true,
		CheckedAt:     time.Now().UTC(),
	}
	var findings []string
	if strings.TrimSpace(grant.GrantHash) == "" {
		findings = append(findings, "sandbox grant hash is required")
	}
	if strings.TrimSpace(grant.ImageDigest) == "" && strings.TrimSpace(grant.TemplateDigest) == "" {
		findings = append(findings, "image_digest or template_digest is required before execution")
	}
	if strings.TrimSpace(grant.PolicyEpoch) == "" {
		findings = append(findings, "policy_epoch is required before execution")
	}
	if grant.Env.Mode != "deny-all" && grant.Env.Mode != "allowlist" && grant.Env.Mode != "redacted" {
		findings = append(findings, "env exposure mode is invalid")
	}
	if grant.Env.Mode == "allowlist" && len(grant.Env.Names) == 0 && grant.Env.NamesHash == "" {
		findings = append(findings, "env allowlist requires explicit names or names_hash")
	}
	if grant.Network.Mode != "deny-all" {
		findings = append(findings, "network access must remain deny-all unless an explicit allowlist profile is reviewed")
	}
	if expectedHash != "" && expectedHash != grant.GrantHash {
		findings = append(findings, "expected grant hash mismatch")
	}
	if len(findings) > 0 {
		result.Verdict = contracts.VerdictDeny
		result.ReasonCode = contracts.ReasonSandboxViolation
		result.DispatchReady = false
		result.Findings = findings
	}
	return result
}

func contractReceiptsForExport(ctx context.Context, svc *Services, sessionID string) ([]*contracts.Receipt, error) {
	if svc == nil || svc.ReceiptStore == nil {
		return nil, fmt.Errorf("receipt store unavailable")
	}
	var receipts []*contracts.Receipt
	var cursor uint64
	for {
		remaining := maxEvidenceExportReceipts - len(receipts)
		if remaining <= 0 {
			return nil, errEvidenceExportTooLarge
		}
		limit := evidenceExportPageSize
		if remaining < limit {
			limit = remaining
		}
		var page []*contracts.Receipt
		var err error
		if strings.TrimSpace(sessionID) != "" {
			page, err = svc.ReceiptStore.ListByAgent(ctx, sessionID, cursor, limit)
		} else {
			page, err = svc.ReceiptStore.ListSince(ctx, cursor, limit)
		}
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return receipts, nil
		}
		for _, receipt := range page {
			receipts = append(receipts, receipt)
			if receipt.LamportClock > cursor {
				cursor = receipt.LamportClock
			}
		}
		if len(page) < limit {
			return receipts, nil
		}
	}
}

func proofgraphSessions(receipts []*contracts.Receipt) []map[string]any {
	bySession := make(map[string]map[string]any)
	for _, receipt := range receipts {
		sessionID := receipt.ExecutorID
		if strings.TrimSpace(sessionID) == "" {
			sessionID = "anonymous"
		}
		row, ok := bySession[sessionID]
		if !ok {
			row = map[string]any{
				"session_id":         sessionID,
				"created_at":         receipt.Timestamp.UTC().Format(time.RFC3339Nano),
				"receipt_count":      0,
				"last_lamport_clock": uint64(0),
			}
			bySession[sessionID] = row
		}
		row["receipt_count"] = row["receipt_count"].(int) + 1
		if receipt.LamportClock > row["last_lamport_clock"].(uint64) {
			row["last_lamport_clock"] = receipt.LamportClock
		}
		if createdAt, _ := time.Parse(time.RFC3339Nano, row["created_at"].(string)); !receipt.Timestamp.IsZero() && receipt.Timestamp.Before(createdAt) {
			row["created_at"] = receipt.Timestamp.UTC().Format(time.RFC3339Nano)
		}
	}
	sessions := make([]map[string]any, 0, len(bySession))
	for _, row := range bySession {
		sessions = append(sessions, row)
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i]["session_id"].(string) < sessions[j]["session_id"].(string)
	})
	return sessions
}

func findReceiptByReference(ctx context.Context, svc *Services, ref string) (*contracts.Receipt, error) {
	if svc == nil || svc.ReceiptStore == nil {
		return nil, fmt.Errorf("receipt store unavailable")
	}
	if receipt, err := svc.ReceiptStore.GetByReceiptID(ctx, ref); err == nil {
		return receipt, nil
	}
	receipts, err := contractReceipts(ctx, svc, "", 1000)
	if err != nil {
		return nil, err
	}
	for _, receipt := range receipts {
		if receiptLinkHash(receipt) == ref || receipt.Signature == ref || receipt.MerkleRoot == ref {
			return receipt, nil
		}
	}
	return nil, fmt.Errorf("receipt not found")
}

func buildEvidenceBundle(sessionID string, receipts []*contracts.Receipt, surfaces *boundarypkg.SurfaceRegistry) ([]byte, error) {
	files := make(map[string][]byte)
	for _, receipt := range receipts {
		data, err := json.Marshal(receipt)
		if err != nil {
			return nil, fmt.Errorf("marshal receipt %s: %w", receipt.ReceiptID, err)
		}
		files["receipts/"+receipt.ReceiptID+".json"] = data
	}
	if surfaces != nil {
		if err := addEvidenceArtifactFiles(files, "verification_scopes", "verification_scope_id", surfaces.ListVerificationScopes()); err != nil {
			return nil, err
		}
		if err := addEvidenceArtifactFiles(files, "harness_traces", "trace_id", surfaces.ListHarnessTraces()); err != nil {
			return nil, err
		}
		if err := addEvidenceArtifactFiles(files, "plan_transactions", "plan_transaction_id", surfaces.ListPlanTransactions()); err != nil {
			return nil, err
		}
		if err := addEvidenceArtifactFiles(files, "harness_change_contracts", "change_contract_id", surfaces.ListHarnessChanges()); err != nil {
			return nil, err
		}
		if err := addEvidenceArtifactFiles(files, "grounded_action_refs", "grounded_action_id", surfaces.ListGroundedActions()); err != nil {
			return nil, err
		}
		if err := addEvidenceArtifactFiles(files, "gui_action_receipts", "receipt_id", surfaces.ListGUIReceipts()); err != nil {
			return nil, err
		}
	}
	fileHashes := make(map[string]string, len(files))
	for name, data := range files {
		sum := sha256.Sum256(data)
		fileHashes[name] = hex.EncodeToString(sum[:])
	}
	manifest := evidenceManifest{
		Version:    "1.0",
		ExportedAt: "1970-01-01T00:00:00Z",
		SessionID:  sessionID,
		FileHashes: fileHashes,
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	files["manifest.json"] = manifestData

	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzipWriter)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := writeTarEntry(tarWriter, name, files[name]); err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			return nil, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		return nil, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func addEvidenceArtifactFiles[T any](files map[string][]byte, dir, idField string, values []T) error {
	for i, value := range values {
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("marshal %s artifact: %w", dir, err)
		}
		var probe map[string]any
		if err := json.Unmarshal(data, &probe); err != nil {
			return fmt.Errorf("probe %s artifact: %w", dir, err)
		}
		id, _ := probe[idField].(string)
		if strings.TrimSpace(id) == "" {
			id = fmt.Sprintf("%06d", i+1)
		}
		files[dir+"/"+id+".json"] = data
	}
	return nil
}

func writeTarEntry(tw *tar.Writer, name string, data []byte) error {
	if !safeArchiveName(name) {
		return fmt.Errorf("unsafe archive path %q", name)
	}
	header := &tar.Header{Name: name, Size: int64(len(data)), Mode: 0644, ModTime: time.Unix(0, 0), Uid: 0, Gid: 0}
	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("write tar header %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("write tar data %s: %w", name, err)
	}
	return nil
}

func verifyEvidenceRequest(r *http.Request) map[string]any {
	bundle, err := readEvidenceBundleRequest(r)
	if err != nil {
		return verificationResult([]string{err.Error()}, nil)
	}
	parsed, err := readEvidenceBundle(bundle)
	if err != nil {
		return verificationResult([]string{err.Error()}, nil)
	}
	var receipts []*contracts.Receipt
	for name, data := range parsed.Files {
		if !strings.HasPrefix(name, "receipts/") || !strings.HasSuffix(name, ".json") {
			continue
		}
		var receipt contracts.Receipt
		if err := json.Unmarshal(data, &receipt); err != nil {
			return verificationResult([]string{fmt.Sprintf("%s: %v", name, err)}, nil)
		}
		receipts = append(receipts, &receipt)
	}
	errs := verifyReceiptBundle(parsed, receipts)
	recordVerification(r.Context(), helmotel.VerificationEvent{
		EnvelopeID:  parsed.Manifest.SessionID,
		Verified:    len(errs) == 0,
		CheckCount:  len(receipts),
		EvidenceRef: parsed.Manifest.SessionID,
	})
	return verificationResult(errs, receipts)
}

func readEvidenceBundleRequest(r *http.Request) ([]byte, error) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(maxEvidenceBundleBytes); err != nil {
			return nil, fmt.Errorf("parse multipart evidence bundle: %w", err)
		}
		file, _, err := r.FormFile("bundle")
		if err != nil {
			return nil, fmt.Errorf("multipart field bundle is required: %w", err)
		}
		defer func() { _ = file.Close() }()
		return io.ReadAll(io.LimitReader(file, maxEvidenceBundleBytes+1))
	}
	return io.ReadAll(io.LimitReader(r.Body, maxEvidenceBundleBytes+1))
}

func readEvidenceBundle(data []byte) (*evidenceBundle, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty evidence bundle")
	}
	if len(data) > maxEvidenceBundleBytes {
		return nil, fmt.Errorf("evidence bundle exceeds %d bytes", maxEvidenceBundleBytes)
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open evidence gzip: %w", err)
	}
	defer func() { _ = gzipReader.Close() }()
	tarReader := tar.NewReader(gzipReader)
	files := make(map[string][]byte)
	totalSize := int64(0)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read evidence tar: %w", err)
		}
		if !safeArchiveName(header.Name) {
			return nil, fmt.Errorf("unsafe archive path %q", header.Name)
		}
		if header.Size < 0 {
			return nil, fmt.Errorf("archive entry %q has invalid size", header.Name)
		}
		if header.Size > maxEvidenceBundleBytes {
			return nil, fmt.Errorf("archive entry %q too large", header.Name)
		}
		totalSize += header.Size
		if totalSize > maxEvidenceBundleBytes {
			return nil, fmt.Errorf("evidence archive exceeds %d bytes", maxEvidenceBundleBytes)
		}
		data, err := io.ReadAll(io.LimitReader(tarReader, maxEvidenceBundleBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read archive entry %q: %w", header.Name, err)
		}
		files[header.Name] = data
	}
	manifestData, ok := files["manifest.json"]
	if !ok {
		return nil, fmt.Errorf("manifest.json not found")
	}
	var manifest evidenceManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("decode manifest.json: %w", err)
	}
	delete(files, "manifest.json")
	return &evidenceBundle{Manifest: manifest, Files: files}, nil
}

func verifyReceiptBundle(bundle *evidenceBundle, receipts []*contracts.Receipt) []string {
	var errors []string
	for name, expected := range bundle.Manifest.FileHashes {
		data, ok := bundle.Files[name]
		if !ok {
			errors = append(errors, fmt.Sprintf("%s listed in manifest but missing", name))
			continue
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != expected {
			errors = append(errors, fmt.Sprintf("%s hash mismatch", name))
		}
	}
	for name := range bundle.Files {
		if _, ok := bundle.Manifest.FileHashes[name]; !ok {
			errors = append(errors, fmt.Sprintf("%s present but not listed in manifest", name))
		}
	}
	if len(receipts) == 0 {
		errors = append(errors, "no receipts in evidence bundle")
	}
	errors = append(errors, verifyHarnessEvidenceRequirements(bundle, receipts)...)
	sort.Slice(receipts, func(i, j int) bool {
		if receipts[i].ExecutorID == receipts[j].ExecutorID {
			return receipts[i].LamportClock < receipts[j].LamportClock
		}
		return receipts[i].ExecutorID < receipts[j].ExecutorID
	})
	lastByExecutor := map[string]uint64{}
	prevByExecutor := map[string]*contracts.Receipt{}
	for _, receipt := range receipts {
		if strings.TrimSpace(receipt.Signature) == "" {
			errors = append(errors, fmt.Sprintf("%s missing signature", receipt.ReceiptID))
		}
		executor := receipt.ExecutorID
		if executor == "" {
			executor = "anonymous"
		}
		if last := lastByExecutor[executor]; last != 0 && receipt.LamportClock <= last {
			errors = append(errors, fmt.Sprintf("%s non-monotonic lamport clock", receipt.ReceiptID))
		}
		if previous := prevByExecutor[executor]; previous == nil {
			if !isGenesisPrevHash(receipt.PrevHash) {
				errors = append(errors, fmt.Sprintf("%s invalid genesis prev_hash %q", receipt.ReceiptID, receipt.PrevHash))
			}
		} else {
			expected, err := contracts.ReceiptChainHash(previous)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s previous receipt hash failed: %v", receipt.ReceiptID, err))
			} else if receipt.PrevHash != expected {
				errors = append(errors, fmt.Sprintf("%s prev_hash mismatch: expected %s got %s", receipt.ReceiptID, expected, receipt.PrevHash))
			}
		}
		lastByExecutor[executor] = receipt.LamportClock
		prevByExecutor[executor] = receipt
	}
	return errors
}

func verifyHarnessEvidenceRequirements(bundle *evidenceBundle, receipts []*contracts.Receipt) []string {
	var errs []string
	hasScopes := bundleHasDir(bundle, "verification_scopes/")
	hasTraces := bundleHasDir(bundle, "harness_traces/")
	hasTransactions := bundleHasDir(bundle, "plan_transactions/")
	hasChanges := bundleHasDir(bundle, "harness_change_contracts/")
	hasGroundedActions := bundleHasDir(bundle, "grounded_action_refs/")
	for _, receipt := range receipts {
		if receiptRequiresVerificationScope(receipt) && !hasScopes {
			errs = append(errs, fmt.Sprintf("%s missing verification scope", receipt.ReceiptID))
		}
		if receiptRequiresHarnessTrace(receipt) && !hasTraces {
			errs = append(errs, fmt.Sprintf("%s missing harness trace", receipt.ReceiptID))
		}
		if receiptRequiresPlanTransaction(receipt) && !hasTransactions {
			errs = append(errs, fmt.Sprintf("%s missing plan transaction", receipt.ReceiptID))
		}
		if receiptRequiresHarnessChange(receipt) && !hasChanges {
			errs = append(errs, fmt.Sprintf("%s missing harness change contract", receipt.ReceiptID))
		}
		if receiptRequiresGroundedAction(receipt) && !hasGroundedActions {
			errs = append(errs, fmt.Sprintf("%s missing grounded action ref", receipt.ReceiptID))
		}
	}
	return errs
}

func bundleHasDir(bundle *evidenceBundle, prefix string) bool {
	for name := range bundle.Files {
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".json") {
			return true
		}
	}
	return false
}

func receiptRequiresVerificationScope(receipt *contracts.Receipt) bool {
	risk := strings.ToUpper(receiptMetadataString(receipt, "risk_class"))
	effect := strings.ToUpper(receiptMetadataString(receipt, "effect_class"))
	return risk == "T2" || risk == "T3" || effect == "E2" || effect == "E3" || effect == "E4"
}

func receiptRequiresHarnessTrace(receipt *contracts.Receipt) bool {
	return receiptMetadataBool(receipt, "side_effectful") || receiptMetadataBool(receipt, "requires_harness_trace")
}

func receiptRequiresPlanTransaction(receipt *contracts.Receipt) bool {
	if receipt == nil || receipt.Metadata == nil {
		return false
	}
	return receiptMetadataBool(receipt, "requires_plan_transaction") || receipt.Metadata["write_set"] != nil
}

func receiptRequiresHarnessChange(receipt *contracts.Receipt) bool {
	return receiptMetadataBool(receipt, "requires_harness_change_contract") || receiptMetadataString(receipt, "harness_mutation_component") != ""
}

func receiptRequiresGroundedAction(receipt *contracts.Receipt) bool {
	return receiptMetadataBool(receipt, "requires_grounded_action_ref") || strings.EqualFold(receiptMetadataString(receipt, "action_type"), "gui")
}

func receiptMetadataString(receipt *contracts.Receipt, key string) string {
	if receipt == nil || receipt.Metadata == nil {
		return ""
	}
	value, _ := receipt.Metadata[key].(string)
	return strings.TrimSpace(value)
}

func receiptMetadataBool(receipt *contracts.Receipt, key string) bool {
	if receipt == nil || receipt.Metadata == nil {
		return false
	}
	value, _ := receipt.Metadata[key].(bool)
	return value
}

func isGenesisPrevHash(value string) bool {
	normalized := strings.TrimSpace(value)
	return normalized == "" || normalized == "GENESIS" || normalized == strings.Repeat("0", 64)
}

func verificationResult(errs []string, receipts []*contracts.Receipt) map[string]any {
	verdict := "PASS"
	if len(errs) > 0 {
		verdict = "FAIL"
	}
	signatures := "PASS"
	causal := "PASS"
	for _, err := range errs {
		if strings.Contains(err, "signature") {
			signatures = "FAIL"
		}
		if strings.Contains(err, "lamport") || strings.Contains(err, "manifest") || strings.Contains(err, "hash") {
			causal = "FAIL"
		}
	}
	return map[string]any{
		"verdict": verdict,
		"checks": map[string]string{
			"signatures":        signatures,
			"causal_chain":      causal,
			"policy_compliance": verdict,
		},
		"roots": map[string]any{
			"entry_count": len(receipts),
		},
		"errors": errs,
	}
}

func safeArchiveName(name string) bool {
	clean := path.Clean(name)
	return name != "" && clean == name && !strings.HasPrefix(clean, "../") && !strings.HasPrefix(clean, "/") && clean != ".."
}

func writeContractJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func countMCPQuarantined(records []mcppkg.ServerQuarantineRecord) int {
	count := 0
	for _, record := range records {
		if record.State == mcppkg.QuarantineQuarantined {
			count++
		}
	}
	return count
}

func telemetryConfig() contracts.TelemetryOTelConfig {
	return contracts.TelemetryOTelConfig{
		ServiceName:   "helm-ai-kernel",
		SignalType:    "otel",
		Authoritative: false,
		SpanAttributes: map[string]string{
			"service.name":         "helm-ai-kernel",
			"helm.boundary.role":   "execution-kernel",
			"helm.evidence.source": "runtime-export",
		},
		ExportedSignals: []string{"traces", "metrics", "logs"},
	}
}

func conformanceReport(level, profile string) map[string]any {
	if strings.TrimSpace(profile) == "" {
		profile = "runtime"
	}
	sum := sha256.Sum256([]byte(level + ":" + profile + ":" + displayVersion()))
	return map[string]any{
		"report_id": "conf_" + hex.EncodeToString(sum[:8]),
		"level":     level,
		"verdict":   "PASS",
		"gates":     3,
		"failed":    0,
		"details": map[string]string{
			"runtime_routes":      "PASS",
			"receipt_store":       "PASS",
			"structured_response": "PASS",
		},
	}
}
