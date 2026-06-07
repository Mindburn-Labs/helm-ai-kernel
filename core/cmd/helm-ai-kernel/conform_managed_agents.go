package main

import (
	"archive/tar"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
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

type managedAgentSigningMaterial struct {
	keyID        string
	publicKeyHex string
	privateKey   ed25519.PrivateKey
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

type managedAgentLiveReport struct {
	SchemaVersion               string                 `json:"schema_version"`
	Provider                    string                 `json:"provider"`
	PromotionReady              bool                   `json:"promotion_ready"`
	Status                      string                 `json:"status"`
	GeneratedAt                 string                 `json:"generated_at"`
	LastVerified                string                 `json:"last_verified"`
	TestedCommit                string                 `json:"tested_commit"`
	TestedTreeHash              string                 `json:"tested_tree_hash"`
	ArtifactURI                 string                 `json:"artifact_uri"`
	EvidencePackSHA256          string                 `json:"evidence_pack_sha256,omitempty"`
	SignerKeyID                 string                 `json:"signer_key_id"`
	WorkerImageDigest           string                 `json:"worker_image_digest"`
	SkillManifestHash           string                 `json:"skill_manifest_hash"`
	SandboxGrantHash            string                 `json:"sandbox_grant_hash"`
	EnvironmentKeySecretRefHash string                 `json:"environment_key_secret_ref_hash"`
	MCPProfileHashes            map[string]string      `json:"mcp_profile_hashes"`
	ScenarioResults             []managedAgentScenario `json:"scenario_results"`
	Blockers                    []string               `json:"blockers"`
	OfflineVerification         string                 `json:"offline_verification"`
	ClaimLimit                  string                 `json:"claim_limit"`
	Sources                     []string               `json:"sources"`
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

func runConformManagedAgents(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "claude-self-hosted" {
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel conform managed-agents claude-self-hosted --provider daytona --live-config <file> --out <dir> --sign")
		return 2
	}
	return runConformClaudeSelfHosted(args[1:], stdout, stderr)
}

func runConformClaudeSelfHosted(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("conform managed-agents claude-self-hosted", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		provider        string
		configPath      string
		outDir          string
		signReport      bool
		promoteRegistry bool
		registryPath    string
		reportRefPath   string
		candidateCommit string
		candidateTree   string
	)
	cmd.StringVar(&provider, "provider", "daytona", "Live self-hosted worker provider fixture")
	cmd.StringVar(&configPath, "live-config", "", "Redacted live evidence config JSON")
	cmd.StringVar(&outDir, "out", filepath.Join("artifacts", "claude-managed-agents-live"), "Output directory for the evidence pack and report")
	cmd.BoolVar(&signReport, "sign", false, "Sign the live evidence report with HELM_SIGNING_KEY_HEX")
	cmd.BoolVar(&promoteRegistry, "promote-registry", false, "Promote compatibility registry entry when all live evidence guards pass")
	cmd.StringVar(&registryPath, "registry", filepath.Join("protocols", "conformance", "v1", "compatibility-registry.json"), "Compatibility registry path")
	cmd.StringVar(&reportRefPath, "report-ref", "", "Optional source-tree path for the sanitized report reference")
	cmd.StringVar(&candidateCommit, "candidate-commit", "", "Expected candidate commit; defaults to HELM_CANDIDATE_COMMIT or git HEAD")
	cmd.StringVar(&candidateTree, "candidate-tree", "", "Expected candidate tree hash; defaults to HELM_CANDIDATE_TREE or git rev-parse HEAD^{tree}")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if configPath == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --live-config is required")
		return 2
	}
	if provider != "daytona" {
		_, _ = fmt.Fprintf(stderr, "Error: unsupported provider %q; only daytona is enabled for the first verified fixture\n", provider)
		return 2
	}
	cfg, err := readManagedAgentLiveConfig(configPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: live config invalid: %v\n", err)
		return 2
	}
	if candidateCommit == "" {
		candidateCommit = firstNonEmpty(os.Getenv("HELM_CANDIDATE_COMMIT"), gitValue("rev-parse", "HEAD"))
	}
	if candidateTree == "" {
		candidateTree = firstNonEmpty(os.Getenv("HELM_CANDIDATE_TREE"), gitValue("rev-parse", "HEAD^{tree}"))
	}

	blockers := validateManagedAgentLiveConfig(cfg, provider, candidateCommit, candidateTree, promoteRegistry)
	if !signReport {
		blockers = append(blockers, "live evidence report must be signed with --sign")
		sort.Strings(blockers)
	}
	report := buildManagedAgentLiveReport(cfg, blockers)
	report.Status = "blocked"
	report.OfflineVerification = "not-run"
	report.PromotionReady = len(blockers) == 0
	if report.PromotionReady {
		report.Status = "ready"
	}

	if err := os.MkdirAll(outDir, 0750); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot create output dir: %v\n", err)
		return 2
	}
	reportPath := filepath.Join(outDir, "live-evidence-report.json")
	if err := writeManagedAgentJSON(reportPath, report); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot write report: %v\n", err)
		return 2
	}

	var signer *managedAgentSigningMaterial
	if signReport {
		signer, err = loadManagedAgentSigningMaterial(cfg.Signer.KeyID)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot load live evidence signing key: %v\n", err)
			return 2
		}
		sig, err := signManagedAgentLiveReport(reportPath, signer)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot sign live evidence report: %v\n", err)
			return 2
		}
		if err := writeManagedAgentJSON(filepath.Join(outDir, "live-evidence-report.sig.json"), sig); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot write report signature: %v\n", err)
			return 2
		}
	}

	packDir := filepath.Join(outDir, "evidence-pack")
	if err := writeManagedAgentEvidenceDirectory(packDir, report, signer); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot write evidence pack: %v\n", err)
		return 2
	}
	verifyReport, err := verifier.VerifyBundleWithOptions(packDir, verifier.VerifyOptions{
		ManagedAgentReceiptPublicKeyHex: managedAgentSignerPublicKeyHex(signer),
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot verify evidence pack: %v\n", err)
		return 2
	}
	if !verifyReport.Verified {
		report.OfflineVerification = "failed"
		report.Blockers = append(report.Blockers, "offline evidence pack verification failed: "+verifyReport.Summary)
		report.PromotionReady = false
		report.Status = "blocked"
	} else {
		report.OfflineVerification = "passed"
	}
	if err := writeManagedAgentJSON(reportPath, report); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot refresh report: %v\n", err)
		return 2
	}
	if err := writeManagedAgentEvidenceDirectory(packDir, report, signer); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot refresh evidence pack: %v\n", err)
		return 2
	}
	verifyReport, err = verifier.VerifyBundleWithOptions(packDir, verifier.VerifyOptions{
		ManagedAgentReceiptPublicKeyHex: managedAgentSignerPublicKeyHex(signer),
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot verify final evidence pack: %v\n", err)
		return 2
	}
	if !verifyReport.Verified {
		_, _ = fmt.Fprintf(stderr, "Error: final evidence pack verification failed: %s\n", verifyReport.Summary)
		return 2
	}

	archivePath := filepath.Join(outDir, "evidence-pack.tar")
	if err := archiveManagedAgentEvidence(packDir, archivePath); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot archive evidence pack: %v\n", err)
		return 2
	}
	packHash, err := fileSHA256(archivePath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot hash evidence pack: %v\n", err)
		return 2
	}
	report.EvidencePackSHA256 = "sha256:" + packHash
	if err := writeManagedAgentJSON(reportPath, report); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot write final report: %v\n", err)
		return 2
	}

	if reportRefPath != "" || promoteRegistry {
		if reportRefPath == "" {
			reportRefPath = filepath.Join("protocols", "conformance", "managed-agents", "claude-self-hosted", "v1", "live-evidence-report.json")
		}
		if err := copyManagedAgentReport(reportPath, reportRefPath); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot write sanitized report reference: %v\n", err)
			return 2
		}
	}

	if promoteRegistry {
		if !report.PromotionReady {
			_, _ = fmt.Fprintln(stderr, "Error: live evidence is incomplete; refusing registry promotion")
			for _, blocker := range report.Blockers {
				_, _ = fmt.Fprintf(stderr, "- %s\n", blocker)
			}
			return 1
		}
		if err := promoteManagedAgentRegistry(registryPath, report); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot promote compatibility registry: %v\n", err)
			return 2
		}
	}

	if !report.PromotionReady {
		_, _ = fmt.Fprintf(stdout, "Claude Managed Agents live evidence blocked; report=%s\n", reportPath)
		for _, blocker := range report.Blockers {
			_, _ = fmt.Fprintf(stdout, "  - %s\n", blocker)
		}
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "Claude Managed Agents live evidence ready\n")
	_, _ = fmt.Fprintf(stdout, "  report: %s\n", reportPath)
	_, _ = fmt.Fprintf(stdout, "  pack:   %s\n", archivePath)
	_, _ = fmt.Fprintf(stdout, "  sha256: %s\n", report.EvidencePackSHA256)
	return 0
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

func buildManagedAgentLiveReport(cfg *managedAgentLiveConfig, blockers []string) managedAgentLiveReport {
	return managedAgentLiveReport{
		SchemaVersion:               managedAgentLiveReportVersion,
		Provider:                    cfg.Provider,
		GeneratedAt:                 time.Now().UTC().Format(time.RFC3339),
		LastVerified:                cfg.LastVerified,
		TestedCommit:                cfg.TestedCommit,
		TestedTreeHash:              cfg.TestedTreeHash,
		ArtifactURI:                 cfg.ArtifactURI,
		SignerKeyID:                 cfg.Signer.KeyID,
		WorkerImageDigest:           cfg.Worker.WorkerImageDigest,
		SkillManifestHash:           cfg.Worker.SkillManifestHash,
		SandboxGrantHash:            cfg.Worker.SandboxGrantHash,
		EnvironmentKeySecretRefHash: "sha256:" + sha256Hex([]byte(cfg.Worker.EnvironmentKeySecretRef)),
		MCPProfileHashes: map[string]string{
			"gateway_url_hash":           cfg.MCP.GatewayURLHash,
			"tunnel_domain_hash":         cfg.MCP.TunnelDomainHash,
			"ca_cert_ref_hash":           cfg.MCP.CACertRefHash,
			"allowed_upstream_host_hash": cfg.MCP.AllowedUpstreamHostHash,
			"schema_pin_hash":            cfg.MCP.SchemaPinHash,
		},
		ScenarioResults: cfg.Scenarios,
		Blockers:        blockers,
		ClaimLimit:      "HELM verified claim is limited to the tested customer-controlled worker and HELM MCP Gateway path; Anthropic MCP tunnels remain research-preview.",
		Sources: []string{
			"https://platform.claude.com/docs/en/managed-agents/self-hosted-sandboxes",
			"https://platform.claude.com/docs/en/managed-agents/self-hosted-sandboxes-security",
			"https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/overview",
		},
	}
}

func writeManagedAgentEvidenceDirectory(root string, report managedAgentLiveReport, signer *managedAgentSigningMaterial) error {
	if err := os.RemoveAll(root); err != nil {
		return err
	}
	files := map[string][]byte{}
	addJSON := func(path string, value any) error {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		files[path] = data
		return nil
	}
	if err := addJSON("01_SCORE.json", map[string]any{
		"schema_version":   "managed_agent_live_score.v1",
		"provider":         report.Provider,
		"promotion_ready":  report.PromotionReady,
		"scenario_count":   len(report.ScenarioResults),
		"blocker_count":    len(report.Blockers),
		"last_verified":    report.LastVerified,
		"tested_commit":    report.TestedCommit,
		"tested_tree_hash": report.TestedTreeHash,
	}); err != nil {
		return err
	}
	if err := addJSON("12_REPORTS/claude-managed-agents-live-report.json", report); err != nil {
		return err
	}
	if err := addJSON("02_PROOFGRAPH/proofgraph.json", map[string]any{
		"schema_version": "managed_agent_live_proofgraph.v1",
		"provider":       report.Provider,
		"scenario_count": len(report.ScenarioResults),
		"ready":          report.PromotionReady,
	}); err != nil {
		return err
	}
	if err := addJSON("08_TAPES/managed-agent-scenarios.json", report.ScenarioResults); err != nil {
		return err
	}
	for _, scenario := range report.ScenarioResults {
		decisionHash := "sha256:" + sha256Hex(mustJSONBytes(scenario))
		receipt := map[string]any{
			"receipt_version": "managed_agent_live_scenario_receipt.v1",
			"receipt_id":      scenario.ReceiptID,
			"receipt_hash":    scenario.ReceiptHash,
			"scenario_id":     scenario.ID,
			"effect_type":     scenario.EffectType,
			"verdict":         scenario.Verdict,
			"reason_code":     scenario.ReasonCode,
			"dispatched":      scenario.Dispatched,
			"evidence_ref":    scenario.EvidenceRef,
			"observed_at":     scenario.ObservedAt,
			"decision_hash":   decisionHash,
		}
		if signer != nil {
			signature, err := signer.sign([]byte(decisionHash))
			if err != nil {
				return err
			}
			receipt["signature_algorithm"] = "ed25519"
			receipt["signature_payload"] = "decision_hash"
			receipt["signer_key_id"] = signer.keyID
			receipt["signing_public_key_hex"] = signer.publicKeyHex
			receipt["signature"] = signature
		}
		if err := addJSON("02_PROOFGRAPH/receipts/"+safeEvidenceName(scenario.ID)+".json", receipt); err != nil {
			return err
		}
		if err := addJSON("12_REPORTS/managed-agent-receipts/"+safeEvidenceName(scenario.ID)+".json", scenario); err != nil {
			return err
		}
	}
	files["03_TELEMETRY/worker-retention.txt"] = []byte("worker log retention evidence is referenced by scenario evidence_ref fields\n")
	files["04_EXPORTS/artifact-uri.txt"] = []byte(report.ArtifactURI + "\n")
	files["05_DIFFS/no-source-diff.txt"] = []byte("live evidence pack contains sanitized reports and receipt references only\n")
	files["06_LOGS/retention.txt"] = []byte("retained logs are hash-referenced in the redacted live config\n")
	files["09_SCHEMAS/claude-self-hosted-live-config.schema-ref.txt"] = []byte("protocols/json-schemas/managed-agents/claude_self_hosted_live_config.v1.schema.json\n")
	if signer != nil {
		if err := addJSON("07_ATTESTATIONS/managed-agent-receipt-signer.json", map[string]string{
			"algorithm":      "ed25519",
			"key_id":         signer.keyID,
			"public_key_hex": signer.publicKeyHex,
		}); err != nil {
			return err
		}
	} else {
		files["07_ATTESTATIONS/unsigned.txt"] = []byte("live evidence report was not signed in this run\n")
	}

	entries := make([]map[string]string, 0, len(files))
	for path, data := range files {
		entries = append(entries, map[string]string{"path": path, "sha256": sha256Hex(data)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i]["path"] < entries[j]["path"] })
	indexData, err := json.MarshalIndent(map[string]any{"entries": entries}, "", "  ")
	if err != nil {
		return err
	}
	files["00_INDEX.json"] = indexData

	for path, data := range files {
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0600); err != nil {
			return err
		}
	}
	if _, err := evidencepkg.SealEvidencePack(context.Background(), root, evidencepkg.SealEvidencePackOptions{
		PackID: "managed-agents-" + safeEvidenceName(report.Provider),
	}); err != nil {
		return err
	}
	return nil
}

func archiveManagedAgentEvidence(root, outPath string) error {
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	tw := tar.NewWriter(out)
	defer tw.Close()
	var paths []string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	}); err != nil {
		return err
	}
	sort.Strings(paths)
	for _, rel := range paths {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		hdr := &tar.Header{Name: rel, Size: int64(len(data)), Mode: 0644, ModTime: time.Unix(0, 0), Uid: 0, Gid: 0, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func loadManagedAgentSigningMaterial(keyID string) (*managedAgentSigningMaterial, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return nil, fmt.Errorf("signer.key_id is required")
	}
	keyHex := strings.TrimSpace(os.Getenv("HELM_SIGNING_KEY_HEX"))
	if keyHex == "" {
		return nil, fmt.Errorf("HELM_SIGNING_KEY_HEX is required for --sign")
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid HELM_SIGNING_KEY_HEX: %w", err)
	}
	var seed []byte
	switch len(keyBytes) {
	case ed25519.SeedSize:
		seed = keyBytes
	case ed25519.PrivateKeySize:
		seed = keyBytes[:ed25519.SeedSize]
	default:
		return nil, fmt.Errorf("HELM_SIGNING_KEY_HEX must encode a 32-byte Ed25519 seed or 64-byte private key")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot derive Ed25519 public key")
	}
	return &managedAgentSigningMaterial{
		keyID:        keyID,
		publicKeyHex: hex.EncodeToString(pub),
		privateKey:   priv,
	}, nil
}

func managedAgentSignerPublicKeyHex(signer *managedAgentSigningMaterial) string {
	if signer == nil {
		return ""
	}
	return signer.publicKeyHex
}

func (s *managedAgentSigningMaterial) sign(data []byte) (string, error) {
	if s == nil || len(s.privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("managed-agent signer is not configured")
	}
	return hex.EncodeToString(ed25519.Sign(s.privateKey, data)), nil
}

func signManagedAgentLiveReport(path string, signer *managedAgentSigningMaterial) (map[string]string, error) {
	if signer == nil {
		return nil, fmt.Errorf("managed-agent signer is not configured")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	sig, err := signer.sign(digest[:])
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"algorithm":      "ed25519",
		"key_id":         signer.keyID,
		"public_key_hex": signer.publicKeyHex,
		"report_hash":    hex.EncodeToString(digest[:]),
		"signature":      sig,
	}, nil
}

func promoteManagedAgentRegistry(path string, report managedAgentLiveReport) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var registry map[string]any
	if err := json.Unmarshal(data, &registry); err != nil {
		return err
	}
	adapters, ok := registry["sandbox_adapters"].([]any)
	if !ok {
		return fmt.Errorf("sandbox_adapters missing or invalid")
	}
	found := false
	for _, item := range adapters {
		entry, ok := item.(map[string]any)
		if !ok || entry["name"] != managedAgentVerifiedName {
			continue
		}
		found = true
		entry["tier"] = "verified"
		entry["status"] = "active"
		entry["last_verified"] = report.LastVerified
		entry["evidence_pack"] = map[string]any{
			"artifact_uri":        report.ArtifactURI,
			"sha256":              report.EvidencePackSHA256,
			"signer":              report.SignerKeyID,
			"tested_commit":       report.TestedCommit,
			"tested_tree_hash":    report.TestedTreeHash,
			"worker_image_digest": report.WorkerImageDigest,
			"skill_manifest_hash": report.SkillManifestHash,
			"sandbox_grant_hash":  report.SandboxGrantHash,
			"mcp_profile_hashes":  report.MCPProfileHashes,
		}
		entry["notes"] = report.ClaimLimit
	}
	if !found {
		return fmt.Errorf("%q entry not found", managedAgentVerifiedName)
	}
	out, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0600)
}

func copyManagedAgentReport(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}

func writeManagedAgentJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0600)
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

func safeEvidenceName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "scenario"
	}
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", " ", "-")
	return replacer.Replace(value)
}

func mustJSONBytes(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func gitValue(args ...string) string {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
