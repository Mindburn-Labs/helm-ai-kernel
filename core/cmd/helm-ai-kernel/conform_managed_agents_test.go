package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConformManagedAgentsRequiresLiveConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runConform([]string{"managed-agents", "claude-self-hosted", "--provider", "daytona"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--live-config is required") {
		t.Fatalf("stderr missing live-config error: %s", stderr.String())
	}
}

func TestConformManagedAgentsBlocksIncompleteLiveEvidence(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "live.json")
	cfg := completeManagedAgentLiveConfig(t)
	cfg.Scenarios = cfg.Scenarios[:1]
	writeTestManagedAgentConfig(t, configPath, cfg)

	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"managed-agents", "claude-self-hosted",
		"--provider", "daytona",
		"--live-config", configPath,
		"--out", filepath.Join(dir, "out"),
		"--candidate-commit", cfg.TestedCommit,
		"--candidate-tree", cfg.TestedTreeHash,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "missing live scenario result") {
		t.Fatalf("stdout missing blocker: %s", stdout.String())
	}
}

func TestConformManagedAgentsWritesVerifiableEvidencePack(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "live.json")
	cfg := completeManagedAgentLiveConfig(t)
	writeTestManagedAgentConfig(t, configPath, cfg)
	t.Setenv("HELM_SIGNING_KEY_HEX", strings.Repeat("11", 32))

	outDir := filepath.Join(dir, "out")
	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"managed-agents", "claude-self-hosted",
		"--provider", "daytona",
		"--live-config", configPath,
		"--out", outDir,
		"--sign",
		"--candidate-commit", cfg.TestedCommit,
		"--candidate-tree", cfg.TestedTreeHash,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	reportPath := filepath.Join(outDir, "live-evidence-report.json")
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report managedAgentLiveReport
	if err := json.Unmarshal(reportData, &report); err != nil {
		t.Fatal(err)
	}
	if !report.PromotionReady || report.OfflineVerification != "passed" || report.EvidencePackSHA256 == "" {
		t.Fatalf("unexpected report readiness: %#v", report)
	}

	var verifyStdout, verifyStderr bytes.Buffer
	verifyCode := runVerifyCmd([]string{"--bundle", filepath.Join(outDir, "evidence-pack.tar"), "--json"}, &verifyStdout, &verifyStderr)
	if verifyCode != 0 {
		t.Fatalf("verify exit code = %d stdout=%s stderr=%s", verifyCode, verifyStdout.String(), verifyStderr.String())
	}
}

func TestConformManagedAgentsPromotesRegistryOnlyWhenReady(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "live.json")
	cfg := completeManagedAgentLiveConfig(t)
	writeTestManagedAgentConfig(t, configPath, cfg)
	t.Setenv("HELM_SIGNING_KEY_HEX", strings.Repeat("22", 32))

	registryPath := filepath.Join(dir, "compatibility-registry.json")
	registry := map[string]any{
		"registry_version": "1.0.0",
		"sandbox_adapters": []map[string]any{{
			"name":   managedAgentVerifiedName,
			"tier":   "compatible",
			"status": "preview",
			"tests":  "core/pkg/connectors/sandbox/claudemanaged",
		}},
	}
	writeTestManagedAgentJSON(t, registryPath, registry)

	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"managed-agents", "claude-self-hosted",
		"--provider", "daytona",
		"--live-config", configPath,
		"--out", filepath.Join(dir, "out"),
		"--sign",
		"--promote-registry",
		"--registry", registryPath,
		"--report-ref", filepath.Join(dir, "live-evidence-report.json"),
		"--candidate-commit", cfg.TestedCommit,
		"--candidate-tree", cfg.TestedTreeHash,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	var updated map[string]any
	if err := json.Unmarshal(data, &updated); err != nil {
		t.Fatal(err)
	}
	adapters := updated["sandbox_adapters"].([]any)
	entry := adapters[0].(map[string]any)
	if entry["tier"] != "verified" || entry["status"] != "active" || entry["last_verified"] != cfg.LastVerified {
		t.Fatalf("registry not promoted: %#v", entry)
	}
	if _, ok := entry["evidence_pack"].(map[string]any); !ok {
		t.Fatalf("registry missing evidence_pack: %#v", entry)
	}
}

func completeManagedAgentLiveConfig(t *testing.T) managedAgentLiveConfig {
	t.Helper()
	cfg := managedAgentLiveConfig{
		SchemaVersion:  managedAgentLiveConfigVersion,
		Provider:       "daytona",
		ArtifactURI:    "gh-artifact://helm-ai-kernel/claude-managed-agents-live/evidence-pack.tar",
		LastVerified:   "2026-05-21",
		TestedCommit:   strings.Repeat("a", 40),
		TestedTreeHash: strings.Repeat("b", 40),
		Signer:         managedAgentSignerConfig{KeyID: "test-signer"},
		Anthropic: managedAgentAnthropicConfig{
			AgentID:       "agent_test",
			AgentVersion:  "2026-05-19",
			SessionID:     "session_test",
			EnvironmentID: "env_test",
			WorkID:        "work_test",
		},
		Worker: managedAgentWorkerConfig{
			WorkerID:                "worker_test",
			WorkerImageDigest:       testManagedAgentHash("image"),
			SkillManifestHash:       testManagedAgentHash("skill"),
			SandboxGrantHash:        testManagedAgentHash("grant"),
			WorkspaceRoot:           "/workspace",
			OutputsRoot:             "/mnt/session/outputs",
			EnvironmentKeySecretRef: "secret://anthropic/environment-key",
			EgressEnforced:          true,
			LogRetentionEnabled:     true,
			TLSRequired:             true,
		},
		Daytona: managedAgentDaytonaConfig{
			WorkspaceRefHash:      testManagedAgentHash("workspace"),
			WorkerRuntimeRefHash:  testManagedAgentHash("runtime"),
			DeploymentAttestation: testManagedAgentHash("deploy"),
			QueueLivenessRef:      testManagedAgentHash("queue"),
			WorkerStopRef:         testManagedAgentHash("stop"),
		},
		MCP: managedAgentMCPConfig{
			RouteThroughHELMGateway: true,
			GatewayURLHash:          testManagedAgentHash("gateway"),
			TunnelDomainHash:        testManagedAgentHash("domain"),
			UpstreamMCPServerID:     "mcp_server_test",
			OAuthResource:           "https://mcp.example.test",
			RequiredScopes:          []string{"tools.read", "tools.call"},
			ProtocolVersion:         "2025-06-18",
			CACertRefHash:           testManagedAgentHash("cert"),
			AllowedUpstreamHostHash: testManagedAgentHash("host"),
			SchemaPinHash:           testManagedAgentHash("schema"),
		},
	}
	for id, req := range managedAgentRequiredScenarios {
		scenario := managedAgentScenario{
			ID:          id,
			EffectType:  "MANAGED_AGENT_TEST",
			Verdict:     req.verdict,
			Dispatched:  req.dispatched,
			ReceiptID:   "receipt_" + safeEvidenceName(id),
			ReceiptHash: testManagedAgentHash(id),
			EvidenceRef: testManagedAgentHash("evidence-" + id),
			ObservedAt:  "2026-05-21T00:00:00Z",
		}
		if req.reason {
			scenario.ReasonCode = "TEST_DENY"
		}
		cfg.Scenarios = append(cfg.Scenarios, scenario)
	}
	return cfg
}

func testManagedAgentHash(seed string) string {
	return "sha256:" + sha256Hex([]byte(seed))
}

func writeTestManagedAgentConfig(t *testing.T, path string, cfg managedAgentLiveConfig) {
	t.Helper()
	writeTestManagedAgentJSON(t, path, cfg)
}

func writeTestManagedAgentJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
