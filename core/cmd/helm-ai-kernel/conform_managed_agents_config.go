package main

// quantum_posture: Configuration checks SHA-256 artifact references.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	managedAgentLiveConfigVersion = "claude_managed_agents_live_config.v1"
	managedAgentLiveReportVersion = "claude_managed_agents_live_evidence_report.v1"
	managedAgentVerifiedName      = "Claude Managed Agents Self-Hosted"
)

type managedAgentLiveConfig struct {
	SchemaVersion  string                      `json:"schema_version"`
	Provider       string                      `json:"provider"`
	ArtifactURI    string                      `json:"artifact_uri"`
	LastVerified   string                      `json:"last_verified"`
	TestedCommit   string                      `json:"tested_commit"`
	TestedTreeHash string                      `json:"tested_tree_hash"`
	Signer         managedAgentSignerConfig    `json:"signer"`
	Anthropic      managedAgentAnthropicConfig `json:"anthropic"`
	Worker         managedAgentWorkerConfig    `json:"worker"`
	Daytona        managedAgentDaytonaConfig   `json:"daytona"`
	MCP            managedAgentMCPConfig       `json:"mcp"`
	Scenarios      []managedAgentScenario      `json:"scenario_results"`
}

type managedAgentSignerConfig struct {
	KeyID string `json:"key_id"`
}

type managedAgentAnthropicConfig struct {
	AgentID       string `json:"agent_id"`
	AgentVersion  string `json:"agent_version"`
	SessionID     string `json:"session_id"`
	EnvironmentID string `json:"environment_id"`
	WorkID        string `json:"work_id"`
}

type managedAgentWorkerConfig struct {
	WorkerID                  string `json:"worker_id"`
	WorkerImageDigest         string `json:"worker_image_digest"`
	SkillManifestHash         string `json:"skill_manifest_hash"`
	SandboxGrantHash          string `json:"sandbox_grant_hash"`
	WorkspaceRoot             string `json:"workspace_root"`
	OutputsRoot               string `json:"outputs_root"`
	EnvironmentKeySecretRef   string `json:"environment_key_secret_ref"`
	OrganizationAPIKeyPresent bool   `json:"organization_api_key_present"`
	EgressEnforced            bool   `json:"egress_enforced"`
	LogRetentionEnabled       bool   `json:"log_retention_enabled"`
	TLSRequired               bool   `json:"tls_required"`
}

type managedAgentDaytonaConfig struct {
	WorkspaceRefHash      string `json:"workspace_ref_hash"`
	WorkerRuntimeRefHash  string `json:"worker_runtime_ref_hash"`
	DeploymentAttestation string `json:"deployment_attestation"`
	QueueLivenessRef      string `json:"queue_liveness_ref"`
	WorkerStopRef         string `json:"worker_stop_ref"`
}

type managedAgentMCPConfig struct {
	RouteThroughHELMGateway bool     `json:"route_through_helm_gateway"`
	GatewayURLHash          string   `json:"gateway_url_hash"`
	TunnelDomainHash        string   `json:"tunnel_domain_hash"`
	UpstreamMCPServerID     string   `json:"upstream_mcp_server_id"`
	OAuthResource           string   `json:"oauth_resource"`
	RequiredScopes          []string `json:"required_scopes"`
	ProtocolVersion         string   `json:"protocol_version"`
	CACertRefHash           string   `json:"ca_cert_ref_hash"`
	AllowedUpstreamHostHash string   `json:"allowed_upstream_host_hash"`
	SchemaPinHash           string   `json:"schema_pin_hash"`
	RawTunnelTargetsAllowed bool     `json:"raw_tunnel_targets_allowed"`
}

type managedAgentScenario struct {
	ID           string `json:"id"`
	EffectType   string `json:"effect_type"`
	Verdict      string `json:"verdict"`
	ReasonCode   string `json:"reason_code,omitempty"`
	Dispatched   bool   `json:"dispatched"`
	ReceiptID    string `json:"receipt_id"`
	ReceiptHash  string `json:"receipt_hash"`
	EvidenceRef  string `json:"evidence_ref"`
	ObservedAt   string `json:"observed_at"`
	ArtifactHash string `json:"artifact_hash,omitempty"`
}

type scenarioRequirement struct {
	verdict    string
	dispatched bool
	reason     bool
}

var managedAgentRequiredScenarios = map[string]scenarioRequirement{
	"allowed-bash":                     {verdict: "ALLOW", dispatched: true},
	"allowed-file-read":                {verdict: "ALLOW", dispatched: true},
	"allowed-file-write":               {verdict: "ALLOW", dispatched: true},
	"allowed-file-list":                {verdict: "ALLOW", dispatched: true},
	"allowed-artifact":                 {verdict: "ALLOW", dispatched: true},
	"allowed-validation":               {verdict: "ALLOW", dispatched: true},
	"allowed-mcp-call":                 {verdict: "ALLOW", dispatched: true},
	"queue-liveness":                   {verdict: "ALLOW", dispatched: true},
	"worker-stop":                      {verdict: "ALLOW", dispatched: true},
	"denied-egress":                    {verdict: "DENY", dispatched: false, reason: true},
	"denied-raw-mcp-tunnel":            {verdict: "DENY", dispatched: false, reason: true},
	"denied-schema-drift":              {verdict: "DENY", dispatched: false, reason: true},
	"denied-insufficient-oauth-scopes": {verdict: "DENY", dispatched: false, reason: true},
	"denied-path-traversal":            {verdict: "DENY", dispatched: false, reason: true},
	"denied-symlink-escape":            {verdict: "DENY", dispatched: false, reason: true},
	"denied-unpinned-skill":            {verdict: "DENY", dispatched: false, reason: true},
	"denied-memory-write":              {verdict: "DENY", dispatched: false, reason: true},
	"denied-missing-ambiguous-session": {verdict: "DENY", dispatched: false, reason: true},
}

func readManagedAgentLiveConfig(path string) (*managedAgentLiveConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg managedAgentLiveConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validateManagedAgentLiveConfig(cfg *managedAgentLiveConfig, provider, candidateCommit, candidateTree string, requireCandidate bool) []string {
	var blockers []string
	add := func(format string, args ...any) {
		blockers = append(blockers, fmt.Sprintf(format, args...))
	}
	if cfg.SchemaVersion != managedAgentLiveConfigVersion {
		add("schema_version must be %s", managedAgentLiveConfigVersion)
	}
	if cfg.Provider != provider {
		add("provider must be %q", provider)
	}
	if cfg.ArtifactURI == "" {
		add("artifact_uri is required")
	}
	if _, err := time.Parse("2006-01-02", cfg.LastVerified); err != nil {
		add("last_verified must be YYYY-MM-DD")
	}
	if cfg.TestedCommit == "" {
		add("tested_commit is required")
	}
	if cfg.TestedTreeHash == "" {
		add("tested_tree_hash is required")
	}
	if requireCandidate && candidateCommit == "" {
		add("candidate commit is required for registry promotion")
	}
	if requireCandidate && candidateTree == "" {
		add("candidate tree hash is required for registry promotion")
	}
	if candidateCommit != "" && cfg.TestedCommit != candidateCommit {
		add("tested_commit %q does not match candidate commit %q", cfg.TestedCommit, candidateCommit)
	}
	if candidateTree != "" && cfg.TestedTreeHash != candidateTree {
		add("tested_tree_hash %q does not match candidate tree %q", cfg.TestedTreeHash, candidateTree)
	}
	if cfg.Signer.KeyID == "" {
		add("signer.key_id is required")
	}
	if cfg.Anthropic.AgentID == "" || cfg.Anthropic.AgentVersion == "" || cfg.Anthropic.SessionID == "" || cfg.Anthropic.EnvironmentID == "" || cfg.Anthropic.WorkID == "" {
		add("anthropic agent/session/environment/work identifiers are required")
	}
	if cfg.Worker.WorkerID == "" {
		add("worker.worker_id is required")
	}
	if !validManagedAgentSHA256(cfg.Worker.WorkerImageDigest) {
		add("worker.worker_image_digest must be sha256:<64 hex>")
	}
	if !validManagedAgentSHA256(cfg.Worker.SkillManifestHash) {
		add("worker.skill_manifest_hash must be sha256:<64 hex>")
	}
	if !validManagedAgentSHA256(cfg.Worker.SandboxGrantHash) {
		add("worker.sandbox_grant_hash must be sha256:<64 hex>")
	}
	if cfg.Worker.WorkspaceRoot != "/workspace" {
		add("worker.workspace_root must be /workspace")
	}
	if cfg.Worker.OutputsRoot != "/mnt/session/outputs" {
		add("worker.outputs_root must be /mnt/session/outputs")
	}
	if cfg.Worker.EnvironmentKeySecretRef == "" {
		add("worker.environment_key_secret_ref is required")
	}
	if cfg.Worker.OrganizationAPIKeyPresent {
		add("worker host must not expose organization-scoped ANTHROPIC_API_KEY")
	}
	if !cfg.Worker.EgressEnforced {
		add("worker egress enforcement must be enabled")
	}
	if !cfg.Worker.LogRetentionEnabled {
		add("worker log retention must be enabled")
	}
	if !cfg.Worker.TLSRequired {
		add("TLS must be required for remote worker/tunnel endpoints")
	}
	if !validManagedAgentSHA256(cfg.Daytona.WorkspaceRefHash) {
		add("daytona.workspace_ref_hash must be sha256:<64 hex>")
	}
	if !validManagedAgentSHA256(cfg.Daytona.WorkerRuntimeRefHash) {
		add("daytona.worker_runtime_ref_hash must be sha256:<64 hex>")
	}
	if !validManagedAgentSHA256(cfg.Daytona.DeploymentAttestation) {
		add("daytona.deployment_attestation must be sha256:<64 hex>")
	}
	if !validManagedAgentSHA256(cfg.Daytona.QueueLivenessRef) {
		add("daytona.queue_liveness_ref must be sha256:<64 hex>")
	}
	if !validManagedAgentSHA256(cfg.Daytona.WorkerStopRef) {
		add("daytona.worker_stop_ref must be sha256:<64 hex>")
	}
	if !cfg.MCP.RouteThroughHELMGateway {
		add("MCP tunnel must route through HELM MCP Gateway")
	}
	if cfg.MCP.RawTunnelTargetsAllowed {
		add("raw MCP tunnel targets must be denied")
	}
	for field, value := range map[string]string{
		"mcp.gateway_url_hash":           cfg.MCP.GatewayURLHash,
		"mcp.tunnel_domain_hash":         cfg.MCP.TunnelDomainHash,
		"mcp.ca_cert_ref_hash":           cfg.MCP.CACertRefHash,
		"mcp.allowed_upstream_host_hash": cfg.MCP.AllowedUpstreamHostHash,
		"mcp.schema_pin_hash":            cfg.MCP.SchemaPinHash,
	} {
		if !validManagedAgentSHA256(value) {
			add("%s must be sha256:<64 hex>", field)
		}
	}
	if cfg.MCP.UpstreamMCPServerID == "" || cfg.MCP.OAuthResource == "" || cfg.MCP.ProtocolVersion == "" || len(cfg.MCP.RequiredScopes) == 0 {
		add("MCP upstream server id, OAuth resource, protocol version, and scopes are required")
	}
	seen := map[string]managedAgentScenario{}
	for _, scenario := range cfg.Scenarios {
		seen[scenario.ID] = scenario
	}
	for id, req := range managedAgentRequiredScenarios {
		scenario, ok := seen[id]
		if !ok {
			add("missing live scenario result %q", id)
			continue
		}
		if scenario.Verdict != req.verdict {
			add("scenario %q verdict must be %s", id, req.verdict)
		}
		if scenario.Dispatched != req.dispatched {
			add("scenario %q dispatched must be %t", id, req.dispatched)
		}
		if scenario.ReceiptID == "" || !validManagedAgentReceiptHash(scenario.ReceiptHash) {
			add("scenario %q must include receipt_id and sha256 receipt_hash", id)
		}
		if scenario.EvidenceRef == "" {
			add("scenario %q must include evidence_ref", id)
		}
		if _, err := time.Parse(time.RFC3339, scenario.ObservedAt); err != nil {
			add("scenario %q observed_at must be RFC3339", id)
		}
		if req.reason && scenario.ReasonCode == "" {
			add("scenario %q must include denial reason_code", id)
		}
	}
	sort.Strings(blockers)
	return blockers
}

func validManagedAgentSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(strings.TrimPrefix(value, "sha256:")) == 64
}

func validManagedAgentReceiptHash(value string) bool {
	if validManagedAgentSHA256(value) {
		return true
	}
	_, err := hex.DecodeString(value)
	return err == nil && len(value) == 64
}
