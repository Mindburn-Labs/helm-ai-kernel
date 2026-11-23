package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

func registerEvidenceContractRoutes(mux routeMux, svc *Services, surfaces *boundarypkg.SurfaceRegistry) {
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
		tenantID, err := authenticatedReceiptTenantID(r.Context())
		if err != nil {
			api.WriteForbidden(w, "Evidence export requires authenticated tenant principal context")
			return
		}
		receipts, err := contractReceiptsForExport(r.Context(), svc, tenantID, req.SessionID)
		if err != nil {
			if errors.Is(err, errEvidenceExportTooLarge) {
				api.WriteError(w, http.StatusRequestEntityTooLarge, "Evidence export too large", fmt.Sprintf("Evidence export is limited to %d receipts; export a narrower session or retention window", maxEvidenceExportReceipts))
				return
			}
			api.WriteInternalR(w, r, err)
			return
		}
		if len(receipts) == 0 {
			api.WriteError(w, http.StatusConflict, "No receipts available", "evidence export requires at least one receipt")
			return
		}
		bundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts(req.SessionID, receipts, surfaces, svc)
		if err != nil {
			api.WriteInternalR(w, r, err)
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
		result := verifyEvidenceRequest(r, svc)
		writeContractJSON(w, http.StatusOK, result)
	})

	mux.HandleFunc("/api/v1/evidence/verification-scopes", protectConfiguredTenantStore(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListVerificationScopes())
		case http.MethodPost:
			var scope contracts.VerificationScope
			if err := json.NewDecoder(r.Body).Decode(&scope); err != nil {
				api.WriteBadRequest(w, "Invalid verification scope JSON")
				return
			}
			tenantID, err := authenticatedReceiptTenantID(r.Context())
			if err != nil {
				api.WriteForbidden(w, "Artifact receipt references require authenticated tenant principal context")
				return
			}
			if err := authorizeArtifactReceiptReferences(r.Context(), svc, tenantID, scope.ReceiptRefs...); err != nil {
				api.WriteBadRequest(w, err.Error())
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
	mux.HandleFunc("/api/v1/evidence/verification-scopes/", protectConfiguredTenantStore(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/evidence/verification-scopes/")
		if id == "" || strings.Contains(id, "/") {
			api.WriteBadRequest(w, "Invalid verification scope id")
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
}

func registerEvidenceEnvelopeContractRoutes(mux routeMux, surfaces *boundarypkg.SurfaceRegistry) {
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
		manifestID, payloadRoute := strings.CutSuffix(suffix, "/payload")
		if manifestID == "" || strings.Contains(manifestID, "/") {
			api.WriteBadRequest(w, "Invalid evidence envelope manifest id")
			return
		}
		manifest, ok := surfaces.GetEnvelope(manifestID)
		if !ok {
			api.WriteNotFound(w, "evidence envelope manifest not found")
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
}
