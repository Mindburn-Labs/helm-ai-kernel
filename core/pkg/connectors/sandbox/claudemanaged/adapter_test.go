package claudemanaged

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conformance"
	sbxconformance "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conformance/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
	"github.com/stretchr/testify/require"
)

type fakeRunner struct {
	calls int
}

func (r *fakeRunner) Run(_ context.Context, _ ExecutionContext, req *actuators.ExecRequest) (*RunnerResult, error) {
	r.calls++
	if len(req.Command) >= 1 && req.Command[0] == "sleep" {
		return &RunnerResult{ExitCode: -1, TimedOut: true, Duration: req.Timeout}, nil
	}
	stdout := []byte{}
	if len(req.Command) > 0 && req.Command[0] == "echo" {
		stdout = []byte(strings.Join(req.Command[1:], " ") + "\n")
	}
	return &RunnerResult{ExitCode: 0, Stdout: stdout, Duration: time.Millisecond}, nil
}

type fakeDispatcher struct {
	calls int
	resp  ToolResponse
}

func (d *fakeDispatcher) Dispatch(_ context.Context, _ ToolRequest) (ToolResponse, error) {
	d.calls++
	return d.resp, nil
}

type testReceiptSigner struct{}

func (testReceiptSigner) Sign(data []byte) (string, error) {
	return strings.TrimPrefix(hashBytes(append([]byte("managed-agent-test|"), data...)), "sha256:"), nil
}

func (testReceiptSigner) SignerKeyID() string { return "managed-agent-test-signer" }

func testConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	return Config{
		WorkerID:                      "worker-1",
		WorkerImageDigest:             "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		SkillManifestHash:             "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		AgentID:                       "agent-1",
		AgentVersion:                  "v1",
		SessionID:                     "session-1",
		EnvironmentID:                 "env-1",
		WorkID:                        "work-1",
		WorkspaceRoot:                 filepath.Join(root, "workspace"),
		OutputsRoot:                   filepath.Join(root, "outputs"),
		EnvironmentKeyConfigured:      true,
		EnvironmentKeyFromSecretStore: true,
		EgressEnforced:                true,
		LogRetentionEnabled:           true,
		TLSRequired:                   true,
		SkillsPinned:                  true,
		MCPGatewayURL:                 "http://127.0.0.1:3000/mcp",
	}
}

func testAdapter(t *testing.T, runner *fakeRunner) *Adapter {
	t.Helper()
	return New(testConfig(t), WithRunner(runner), WithReceiptSigner(testReceiptSigner{}), WithClock(func() time.Time {
		return time.Unix(100, 0).UTC()
	}))
}

func TestClaudeManaged_ConformanceSuite(t *testing.T) {
	adapter := testAdapter(t, &fakeRunner{})
	suite := conformance.NewSuite()
	sbxconformance.RegisterSandboxTests(suite, adapter)

	results := suite.Run(conformance.LevelL3)
	for _, result := range results {
		t.Run(result.Name, func(t *testing.T) {
			if !result.Passed {
				t.Fatalf("FAIL: %s - %s", result.TestID, result.Error)
			}
		})
	}
}

func TestPreflightDeniesUnsafeConfig(t *testing.T) {
	cases := map[string]func(*Config){
		"missing image digest":       func(c *Config) { c.WorkerImageDigest = "" },
		"org api key present":        func(c *Config) { c.OrganizationAPIKeyPresent = true },
		"missing environment key":    func(c *Config) { c.EnvironmentKeyConfigured = false },
		"environment key not secret": func(c *Config) { c.EnvironmentKeyFromSecretStore = false },
		"unpinned skills": func(c *Config) {
			c.SkillsPinned = false
			c.SkillManifestHash = ""
		},
		"egress disabled":          func(c *Config) { c.EgressEnforced = false },
		"logs disabled":            func(c *Config) { c.LogRetentionEnabled = false },
		"raw mcp tunnel":           func(c *Config) { c.AllowRawMCPTunnelTargets = true },
		"insecure remote endpoint": func(c *Config) { c.RemoteEndpoint = "http://worker.example" },
		"incomplete tunnel evidence": func(c *Config) {
			c.Tunnel.Enabled = true
			c.Tunnel.RouteThroughHELMGateway = true
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(t)
			mutate(&cfg)
			report, err := New(cfg, WithRunner(&fakeRunner{}), WithReceiptSigner(testReceiptSigner{})).Preflight(t.Context())
			require.NoError(t, err)
			require.False(t, report.StrictPassed)
		})
	}
}

func TestPreflightRequiresNonPreviewReceiptSigner(t *testing.T) {
	cfg := testConfig(t)
	report, err := New(cfg, WithRunner(&fakeRunner{})).Preflight(t.Context())
	require.NoError(t, err)
	require.False(t, report.StrictPassed)
	require.False(t, checkReceiptSigner(nil).Passed)

	report, err = New(cfg, WithRunner(&fakeRunner{}), WithReceiptSigner(deterministicPreviewSigner{})).Preflight(t.Context())
	require.NoError(t, err)
	require.False(t, report.StrictPassed)
	require.False(t, checkReceiptSigner(deterministicPreviewSigner{}).Passed)

	report, err = New(cfg, WithRunner(&fakeRunner{}), WithReceiptSigner(testReceiptSigner{})).Preflight(t.Context())
	require.NoError(t, err)
	require.True(t, report.StrictPassed)
}

func TestFilesystemRejectsTraversalSymlinkEscapeAndUndeclaredWrites(t *testing.T) {
	adapter := testAdapter(t, &fakeRunner{})
	handle, err := adapter.Create(t.Context(), &actuators.SandboxSpec{
		Runtime:   "default",
		Resources: actuators.ResourceSpec{MemoryMB: 128, Timeout: time.Second},
		Egress:    actuators.EgressPolicy{Disabled: true},
		Mounts: []actuators.MountSpec{
			{Target: "/workspace/allowed", ReadOnly: false},
			{Target: "/workspace/readonly", ReadOnly: true},
		},
	})
	require.NoError(t, err)

	require.NoError(t, adapter.WriteFile(t.Context(), handle.ID, "/workspace/allowed/file.txt", []byte("ok")))
	require.Error(t, adapter.WriteFile(t.Context(), handle.ID, "/workspace/readonly/file.txt", []byte("deny")))
	require.Error(t, adapter.WriteFile(t.Context(), handle.ID, "/workspace/other/file.txt", []byte("deny")))
	require.Error(t, adapter.WriteFile(t.Context(), handle.ID, "../escape.txt", []byte("deny")))

	outside := filepath.Join(t.TempDir(), "outside.txt")
	require.NoError(t, os.WriteFile(outside, []byte("secret"), 0o644))
	state, err := adapter.runningState(handle.ID)
	require.NoError(t, err)
	require.NoError(t, os.Symlink(outside, filepath.Join(state.workspace, "allowed", "link")))
	_, err = adapter.ReadFile(t.Context(), handle.ID, "/workspace/allowed/link")
	require.Error(t, err)
}

func TestCreateUsesIsolatedSandboxRoots(t *testing.T) {
	cfg := testConfig(t)
	cfg.WorkID = ""
	cfg.SessionID = ""
	adapter := New(cfg, WithRunner(&fakeRunner{}), WithReceiptSigner(testReceiptSigner{}))

	first, err := adapter.Create(t.Context(), basicSpec())
	require.NoError(t, err)
	second, err := adapter.Create(t.Context(), basicSpec())
	require.NoError(t, err)
	require.NotEqual(t, first.ID, second.ID)

	require.NoError(t, adapter.WriteFile(t.Context(), first.ID, "/workspace/only-first.txt", []byte("secret")))
	entries, err := adapter.ListFiles(t.Context(), second.ID, "/workspace")
	require.NoError(t, err)
	for _, entry := range entries {
		require.NotEqual(t, "/workspace/only-first.txt", entry.Path)
	}

	firstState, err := adapter.runningState(first.ID)
	require.NoError(t, err)
	secondState, err := adapter.runningState(second.ID)
	require.NoError(t, err)
	require.NotEqual(t, firstState.workspace, secondState.workspace)
	require.NotEqual(t, firstState.outputs, secondState.outputs)
	require.Contains(t, firstState.workspace, first.ID)
	require.Contains(t, secondState.workspace, second.ID)
}

func TestExecReceiptBindsManagedAgentSpec(t *testing.T) {
	adapter := testAdapter(t, &fakeRunner{})
	handle, err := adapter.Create(t.Context(), &actuators.SandboxSpec{
		Runtime:   "sha256:worker",
		Resources: actuators.ResourceSpec{MemoryMB: 128, Timeout: time.Second},
		Egress: actuators.EgressPolicy{
			Disabled: true,
			DefaultAllowlist: []actuators.EgressRule{
				{Host: "api.anthropic.com", Port: 443, Protocol: "tcp"},
			},
		},
	})
	require.NoError(t, err)

	result, err := adapter.Exec(t.Context(), handle.ID, &actuators.ExecRequest{Command: []string{"echo", "receipt"}})
	require.NoError(t, err)
	require.Equal(t, ProviderID, result.Receipt.Provider)
	require.NotEmpty(t, result.Receipt.SandboxSpecHash)
	require.NotEmpty(t, result.Receipt.ResourceLimitsHash)
	require.NotEmpty(t, result.Receipt.EgressPolicyHash)
	require.Equal(t, actuators.EffectExecShell, result.Receipt.Effect)
	require.Equal(t, testConfig(t).WorkerImageDigest, handle.Metadata[metadataImageDigest])
}

func TestAllowEgressRejectsOutsideGrant(t *testing.T) {
	adapter := testAdapter(t, &fakeRunner{})
	handle, err := adapter.Create(t.Context(), &actuators.SandboxSpec{
		Runtime:   "default",
		Resources: actuators.ResourceSpec{MemoryMB: 128, Timeout: time.Second},
		Egress: actuators.EgressPolicy{
			Disabled: false,
			DefaultAllowlist: []actuators.EgressRule{
				{Host: "api.anthropic.com", Port: 443, Protocol: "tcp"},
			},
		},
	})
	require.NoError(t, err)

	require.NoError(t, adapter.AllowEgress(t.Context(), handle.ID, []actuators.EgressRule{{Host: "api.anthropic.com", Port: 443, Protocol: "tcp"}}))
	require.Error(t, adapter.AllowEgress(t.Context(), handle.ID, []actuators.EgressRule{{Host: "example.com", Port: 443, Protocol: "tcp"}}))
}

func TestCreateDeniesUnrestrictedEgressSpec(t *testing.T) {
	cases := map[string]actuators.EgressPolicy{
		"enabled without allowlist": {Disabled: false},
		"wildcard host": {
			Disabled: false,
			DefaultAllowlist: []actuators.EgressRule{
				{Host: "*", Port: 443, Protocol: "tcp"},
			},
		},
		"any cidr": {
			Disabled: false,
			DefaultAllowlist: []actuators.EgressRule{
				{Host: "0.0.0.0/0", Port: 0, Protocol: "tcp"},
			},
		},
	}

	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			adapter := testAdapter(t, &fakeRunner{})
			_, err := adapter.Create(t.Context(), &actuators.SandboxSpec{
				Runtime:   "default",
				Resources: actuators.ResourceSpec{MemoryMB: 128, Timeout: time.Second},
				Egress:    policy,
			})
			require.Error(t, err)
		})
	}
}

func TestWorkerShimDeniesMemoryAndRawMCPWithoutDispatch(t *testing.T) {
	runner := &fakeRunner{}
	adapter := testAdapter(t, runner)
	handle, err := adapter.Create(t.Context(), &actuators.SandboxSpec{
		Runtime:   "default",
		Resources: actuators.ResourceSpec{MemoryMB: 128, Timeout: time.Second},
		Egress:    actuators.EgressPolicy{Disabled: true},
	})
	require.NoError(t, err)

	shim := WorkerShim{Actuator: adapter}
	resp, err := shim.HandleTool(t.Context(), ToolRequest{RequestID: "mem-1", SandboxID: handle.ID, Class: ToolMemoryWrite})
	require.NoError(t, err)
	require.False(t, resp.Allowed)
	require.True(t, resp.IsError)
	require.Equal(t, string(contracts.ReasonSessionRiskDeny), resp.ReasonCode)
	require.Equal(t, 0, runner.calls)

	resp, err = shim.HandleTool(t.Context(), ToolRequest{RequestID: "mcp-1", SandboxID: handle.ID, Class: ToolMCP, Metadata: map[string]string{"route": "raw"}})
	require.NoError(t, err)
	require.False(t, resp.Allowed)
	require.Equal(t, string(contracts.ReasonSandboxViolation), resp.ReasonCode)
}

func TestWorkerShimMCPGatewayResponseGetsManagedAgentReceipt(t *testing.T) {
	cfg := testConfig(t)
	cfg.Tunnel = MCPTunnelProfile{
		Enabled:                 true,
		RouteThroughHELMGateway: true,
		TunnelDomainHash:        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		UpstreamMCPServerID:     "mcp-internal-1",
		OAuthResource:           "https://mcp.internal.example",
		RequiredScopes:          []string{"tools.read"},
		ProtocolVersion:         "2025-03-26",
		CACertRefHash:           "sha256:4444444444444444444444444444444444444444444444444444444444444444",
		AllowedUpstreamHostHash: "sha256:5555555555555555555555555555555555555555555555555555555555555555",
	}
	adapter := New(cfg, WithRunner(&fakeRunner{}), WithReceiptSigner(testReceiptSigner{}), WithClock(func() time.Time {
		return time.Unix(100, 0).UTC()
	}))
	handle, err := adapter.Create(t.Context(), &actuators.SandboxSpec{
		Runtime:   "default",
		Resources: actuators.ResourceSpec{MemoryMB: 128, Timeout: time.Second},
		Egress:    actuators.EgressPolicy{Disabled: true},
	})
	require.NoError(t, err)

	dispatcher := &fakeDispatcher{resp: ToolResponse{
		Allowed:   true,
		Content:   "gateway ok",
		ReceiptID: "gateway-receipt-1",
	}}
	shim := WorkerShim{
		Actuator:   adapter,
		Dispatcher: dispatcher,
		Clock: func() time.Time {
			return time.Unix(202, 0).UTC()
		},
	}
	resp, err := shim.HandleTool(t.Context(), ToolRequest{
		RequestID: "mcp-allowed-1",
		SandboxID: handle.ID,
		ToolName:  "internal.search",
		Class:     ToolMCP,
		Target:    "mcp-internal-1/internal.search",
		Metadata:  map[string]string{"route": "helm-mcp-gateway"},
	})
	require.NoError(t, err)
	require.Equal(t, 1, dispatcher.calls)
	require.True(t, resp.Allowed)
	require.NotEqual(t, "gateway-receipt-1", resp.ReceiptID)
	require.Equal(t, "gateway-receipt-1", resp.StructuredContent["mcp_gateway_receipt_ref"])
	require.Equal(t, ReceiptVersionManagedAgentExecution, resp.StructuredContent["managed_agent_receipt_schema"])
	require.Len(t, resp.StructuredContent["managed_agent_receipt_hash"], 64)

	receipt, err := adapter.managedReceiptForTool(ToolRequest{
		RequestID: "mcp-denied-1",
		SandboxID: handle.ID,
		ToolName:  "internal.search",
		Class:     ToolMCP,
		Target:    "mcp-internal-1/internal.search",
	}, contracts.VerdictDeny, contracts.ReasonSandboxViolation, "schema drift", nil, "gateway-denial-1", time.Unix(203, 0).UTC())
	require.NoError(t, err)
	require.Len(t, receipt.MCPProfiles, 1)
	require.Equal(t, "helm-mcp-gateway", receipt.MCPProfiles[0].Route)
	require.Equal(t, "mcp-internal-1", receipt.MCPProfiles[0].UpstreamMCPServerID)
	require.Equal(t, "gateway-denial-1", receipt.DeniedEffects[0].ReceiptRef)
}

func TestWorkerShimEmitsManagedAgentReceiptMetadata(t *testing.T) {
	adapter := testAdapter(t, &fakeRunner{})
	handle, err := adapter.Create(t.Context(), &actuators.SandboxSpec{
		Runtime:   "default",
		Resources: actuators.ResourceSpec{MemoryMB: 128, Timeout: time.Second},
		Egress:    actuators.EgressPolicy{Disabled: true},
	})
	require.NoError(t, err)

	shim := WorkerShim{
		Actuator: adapter,
		Clock: func() time.Time {
			return time.Unix(200, 0).UTC()
		},
	}

	resp, err := shim.HandleTool(t.Context(), ToolRequest{
		RequestID: "write-1",
		SandboxID: handle.ID,
		ToolName:  "file.write",
		Class:     ToolFileWrite,
		Path:      "/workspace/receipt.txt",
		Data:      []byte("receipt"),
	})
	require.NoError(t, err)
	require.True(t, resp.Allowed)
	require.NotEmpty(t, resp.ReceiptID)
	require.Equal(t, ReceiptVersionManagedAgentExecution, resp.StructuredContent["managed_agent_receipt_schema"])
	require.Len(t, resp.StructuredContent["managed_agent_receipt_hash"], 64)

	receipt, err := adapter.managedReceiptForTool(ToolRequest{
		RequestID: "deny-1",
		SandboxID: handle.ID,
		ToolName:  "memory.write",
		Class:     ToolMemoryWrite,
	}, contracts.VerdictDeny, contracts.ReasonSessionRiskDeny, "memory unsupported", nil, "", time.Unix(201, 0).UTC())
	require.NoError(t, err)
	require.Equal(t, ReceiptVersionManagedAgentExecution, receipt.ReceiptVersion)
	require.Equal(t, "agent-1", receipt.AgentID)
	require.Equal(t, "session-1", receipt.SessionID)
	require.Equal(t, "work-1", receipt.WorkID)
	require.Equal(t, testConfig(t).WorkerImageDigest, receipt.Worker.WorkerImageDigest)
	require.True(t, strings.HasPrefix(receipt.SandboxGrantHash, "sha256:"))
	require.Len(t, receipt.ReceiptHash, 64)
	require.NotEmpty(t, receipt.Signature)
	require.Equal(t, testReceiptSigner{}.SignerKeyID(), receipt.SignerKeyID)
	require.Len(t, receipt.ToolActions, 1)
	require.Equal(t, "MANAGED_AGENT_MEMORY_WRITE", receipt.ToolActions[0].EffectType)
	require.Equal(t, contracts.VerdictDeny, receipt.ToolActions[0].Verdict)
	require.Len(t, receipt.DeniedEffects, 1)
	require.Equal(t, string(contracts.ReasonSessionRiskDeny), receipt.DeniedEffects[0].ReasonCode)
}
