package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	runtimesandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtime/sandbox"
)

func registerSandboxContractRoutes(mux routeMux, surfaces *boundarypkg.SurfaceRegistry) {
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
		grantID := strings.TrimPrefix(r.URL.Path, "/api/v1/sandbox/grants/")
		if grantID == "" || strings.Contains(grantID, "/") {
			api.WriteBadRequest(w, "Invalid sandbox grant id")
			return
		}
		grant, ok := surfaces.GetSandboxGrant(grantID)
		if !ok {
			api.WriteNotFound(w, "sandbox grant not found")
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
