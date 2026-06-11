package claudemanaged

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
	"github.com/stretchr/testify/require"
)

func TestAdapterLifecycleListFilesLogsAndStateBranches(t *testing.T) {
	runner := &fakeRunner{}
	adapter := testAdapter(t, runner)
	handle, err := adapter.Create(context.Background(), basicSpec())
	require.NoError(t, err)

	_, err = adapter.Resume(context.Background(), handle.ID)
	require.ErrorIs(t, err, actuators.ErrNotSupported)
	require.ErrorIs(t, adapter.Pause(context.Background(), handle.ID), actuators.ErrNotSupported)
	require.ErrorIs(t, adapter.Terminate(context.Background(), "missing"), actuators.ErrSandboxNotFound)
	_, err = adapter.ListFiles(context.Background(), "missing", "/workspace")
	require.ErrorIs(t, err, actuators.ErrSandboxNotFound)
	_, err = adapter.Logs(context.Background(), "missing", nil)
	require.ErrorIs(t, err, actuators.ErrSandboxNotFound)

	require.NoError(t, adapter.WriteFile(context.Background(), handle.ID, "b.txt", []byte("b")))
	require.NoError(t, adapter.WriteFile(context.Background(), handle.ID, "/workspace/a.txt", []byte("a")))
	require.NoError(t, adapter.WriteFile(context.Background(), handle.ID, "/mnt/session/outputs/out.txt", []byte("out")))

	entries, err := adapter.ListFiles(context.Background(), handle.ID, "/workspace")
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(entries), 2)
	require.Equal(t, "/workspace/a.txt", entries[0].Path)

	missingEntries, err := adapter.ListFiles(context.Background(), handle.ID, "/workspace/missing")
	require.NoError(t, err)
	require.Empty(t, missingEntries)

	_, err = adapter.Exec(context.Background(), handle.ID, nil)
	require.ErrorContains(t, err, "command is required")
	_, err = adapter.Exec(context.Background(), handle.ID, &actuators.ExecRequest{Command: []string{}})
	require.ErrorContains(t, err, "command is required")

	result, err := adapter.Exec(context.Background(), handle.ID, &actuators.ExecRequest{
		Command: []string{"echo", "hello"},
		WorkDir: "/workspace",
	})
	require.NoError(t, err)
	require.True(t, result.Success())

	logs, err := adapter.Logs(context.Background(), handle.ID, nil)
	require.NoError(t, err)
	require.NotEmpty(t, logs)
	tail, err := adapter.Logs(context.Background(), handle.ID, &actuators.LogOptions{Tail: 1})
	require.NoError(t, err)
	require.Len(t, tail, 1)

	adapter.mu.Lock()
	adapter.sandboxes[handle.ID].handle.Status = actuators.StatusPaused
	adapter.mu.Unlock()
	_, err = adapter.Exec(context.Background(), handle.ID, &actuators.ExecRequest{Command: []string{"echo", "x"}})
	require.ErrorContains(t, err, "is not running")

	adapter.mu.Lock()
	adapter.sandboxes[handle.ID].handle.Status = actuators.StatusRunning
	adapter.mu.Unlock()
	require.NoError(t, adapter.Terminate(context.Background(), handle.ID))
	_, err = adapter.ReadFile(context.Background(), handle.ID, "/workspace/a.txt")
	require.ErrorIs(t, err, actuators.ErrSandboxTerminated)
}

func TestAdapterEgressControllerAndIDBranches(t *testing.T) {
	egress := &recordingEgress{}
	cfg := testConfig(t)
	cfg.WorkID = ""
	cfg.SessionID = "session-only"
	adapter := New(cfg, WithRunner(&fakeRunner{}), WithReceiptSigner(testReceiptSigner{}), WithEgressController(egress), WithClock(func() time.Time {
		return time.Unix(300, 0).UTC()
	}))
	handle, err := adapter.Create(context.Background(), &actuators.SandboxSpec{
		Runtime:   "default",
		Resources: actuators.ResourceSpec{MemoryMB: 128, Timeout: time.Second},
		Egress: actuators.EgressPolicy{
			Disabled: false,
			DefaultAllowlist: []actuators.EgressRule{
				{Host: "api.anthropic.com", Port: 443},
			},
		},
	})
	require.NoError(t, err)
	require.Equal(t, "claude-session-session-only-1", handle.ID)
	require.NoError(t, adapter.AllowEgress(context.Background(), handle.ID, nil))
	require.NoError(t, adapter.AllowEgress(context.Background(), handle.ID, []actuators.EgressRule{{Host: "api.anthropic.com", Port: 443}}))
	require.Equal(t, 1, egress.calls)
	require.Equal(t, "api.anthropic.com", egress.rules[0].Host)

	egress.err = errors.New("controller failed")
	err = adapter.AllowEgress(context.Background(), handle.ID, []actuators.EgressRule{{Host: "api.anthropic.com", Port: 443}})
	require.ErrorContains(t, err, "controller failed")

	disabledAdapter := testAdapter(t, &fakeRunner{})
	disabledHandle, err := disabledAdapter.Create(context.Background(), basicSpec())
	require.NoError(t, err)
	err = disabledAdapter.AllowEgress(context.Background(), disabledHandle.ID, []actuators.EgressRule{{Host: "api.anthropic.com", Port: 443}})
	require.ErrorIs(t, err, actuators.ErrNotSupported)

	cfg = testConfig(t)
	cfg.WorkID = ""
	cfg.SessionID = ""
	generic := New(cfg, WithRunner(&fakeRunner{}), WithReceiptSigner(testReceiptSigner{}))
	genericHandle, err := generic.Create(context.Background(), basicSpec())
	require.NoError(t, err)
	require.Equal(t, "claude-managed-1", genericHandle.ID)
	generic.clock = nil
	require.False(t, generic.now().IsZero())
}

func TestReceiptSignerAndPreflightBranches(t *testing.T) {
	cfg := testConfig(t)
	adapter := New(cfg, WithRunner(&fakeRunner{}), WithReceiptSigner(failingSigner{}))
	handle, err := adapter.Create(context.Background(), basicSpec())
	require.NoError(t, err)
	_, err = adapter.managedReceiptForTool(ToolRequest{
		RequestID: "sign-1",
		SandboxID: handle.ID,
		Class:     ToolBash,
		Command:   []string{"echo", "x"},
	}, contracts.VerdictAllow, "", "", nil, "", time.Unix(400, 0).UTC())
	require.ErrorContains(t, err, "sign managed-agent receipt")

	require.False(t, checkWorkerIdentity(Config{}).Passed)
	require.False(t, checkWorkspaceRoots(Config{}).Passed)
	tlsInvalid := testConfig(t)
	tlsInvalid.RemoteEndpoint = "://bad"
	require.False(t, checkTLS(tlsInvalid).Passed)
	tlsOK := testConfig(t)
	tlsOK.RemoteEndpoint = "https://worker.example"
	require.True(t, checkTLS(tlsOK).Passed)
	mcpOK := testConfig(t)
	mcpOK.Tunnel = MCPTunnelProfile{
		Enabled:                 true,
		RouteThroughHELMGateway: true,
		TunnelDomainHash:        "sha256:tunnel",
		UpstreamMCPServerID:     "upstream",
		OAuthResource:           "https://mcp.example",
		RequiredScopes:          []string{"tools.read"},
		ProtocolVersion:         "2025-03-26",
		CACertRefHash:           "sha256:ca",
		AllowedUpstreamHostHash: "sha256:host",
	}
	require.True(t, checkMCPGateway(mcpOK).Passed)
}

func TestLocalCommandRunnerBranches(t *testing.T) {
	runner := LocalCommandRunner{}
	execCtx := ExecutionContext{WorkspaceRoot: t.TempDir(), OutputsRoot: t.TempDir()}

	_, err := runner.Run(context.Background(), execCtx, nil)
	require.ErrorContains(t, err, "command is required")

	ok, err := runner.Run(context.Background(), execCtx, &actuators.ExecRequest{
		Command: []string{"/bin/sh", "-c", "printf %s \"$HELLO\""},
		WorkDir: execCtx.WorkspaceRoot,
		Env:     map[string]string{"HELLO": "world"},
		Stdin:   []byte("ignored"),
	})
	require.NoError(t, err)
	require.Equal(t, 0, ok.ExitCode)
	require.Equal(t, []byte("world"), ok.Stdout)

	t.Setenv("OPENAI_API_KEY", "sk-host-secret")
	sanitized, err := runner.Run(context.Background(), execCtx, &actuators.ExecRequest{
		Command: []string{"/bin/sh", "-c", "printf %s \"${OPENAI_API_KEY:-absent}\""},
		WorkDir: execCtx.WorkspaceRoot,
	})
	require.NoError(t, err)
	require.Equal(t, 0, sanitized.ExitCode)
	require.Equal(t, []byte("absent"), sanitized.Stdout)

	_, err = runner.Run(context.Background(), execCtx, &actuators.ExecRequest{
		Command: []string{"/bin/sh", "-c", "printf should-not-run"},
		WorkDir: execCtx.WorkspaceRoot,
		Env:     map[string]string{"ANTHROPIC_API_KEY": "sk-request"},
	})
	require.ErrorContains(t, err, "secret-bearing env var")

	failed, err := runner.Run(context.Background(), execCtx, &actuators.ExecRequest{
		Command: []string{"/bin/sh", "-c", "exit 7"},
		WorkDir: execCtx.WorkspaceRoot,
	})
	require.NoError(t, err)
	require.Equal(t, 7, failed.ExitCode)

	missing, err := runner.Run(context.Background(), execCtx, &actuators.ExecRequest{
		Command: []string{"/definitely/not/a-command"},
		WorkDir: execCtx.WorkspaceRoot,
	})
	require.NoError(t, err)
	require.Equal(t, -1, missing.ExitCode)

	timedOut, err := runner.Run(context.Background(), execCtx, &actuators.ExecRequest{
		Command: []string{"/bin/sh", "-c", "sleep 1"},
		WorkDir: execCtx.WorkspaceRoot,
		Timeout: time.Millisecond,
	})
	require.NoError(t, err)
	require.True(t, timedOut.TimedOut)
	require.Equal(t, -1, timedOut.ExitCode)
}

func TestWorkerShimAdditionalToolBranches(t *testing.T) {
	adapter := testAdapter(t, &fakeRunner{})
	handle, err := adapter.Create(context.Background(), basicSpec())
	require.NoError(t, err)
	require.NoError(t, adapter.WriteFile(context.Background(), handle.ID, "/workspace/read.txt", []byte("readable")))
	require.NoError(t, adapter.WriteFile(context.Background(), handle.ID, "/workspace/list.txt", []byte("listed")))

	shim := WorkerShim{
		Actuator: adapter,
		Clock: func() time.Time {
			return time.Unix(500, 0).UTC()
		},
	}

	_, err = (WorkerShim{}).HandleTool(context.Background(), ToolRequest{Class: ToolBash})
	require.ErrorContains(t, err, "requires actuator")

	resp, err := shim.HandleTool(context.Background(), ToolRequest{
		SandboxID: handle.ID,
		Class:     ToolBash,
		Command:   []string{"echo", "shim"},
	})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(resp.ReceiptID, "sha256:"))
	require.Equal(t, float64(0), float64(resp.StructuredContent["exit_code"].(int)))

	resp, err = shim.HandleTool(context.Background(), ToolRequest{
		RequestID: "read-1",
		SandboxID: handle.ID,
		Class:     ToolFileRead,
		Path:      "/workspace/read.txt",
	})
	require.NoError(t, err)
	require.True(t, resp.Allowed)
	require.Equal(t, "readable", resp.Content)

	resp, err = shim.HandleTool(context.Background(), ToolRequest{
		RequestID: "list-1",
		SandboxID: handle.ID,
		Class:     ToolFileList,
		Path:      "/workspace",
	})
	require.NoError(t, err)
	var entries []actuators.FileEntry
	require.NoError(t, json.Unmarshal([]byte(resp.Content), &entries))
	require.NotEmpty(t, entries)

	resp, err = shim.HandleTool(context.Background(), ToolRequest{
		RequestID: "artifact-1",
		SandboxID: handle.ID,
		Class:     ToolOutputArtifact,
		Data:      []byte("artifact"),
	})
	require.NoError(t, err)
	require.True(t, resp.Allowed)
	artifact, err := adapter.ReadFile(context.Background(), handle.ID, "/mnt/session/outputs/artifact-1")
	require.NoError(t, err)
	require.Equal(t, []byte("artifact"), artifact)

	resp, err = shim.HandleTool(context.Background(), ToolRequest{
		RequestID: "mcp-no-dispatcher",
		SandboxID: handle.ID,
		Class:     ToolMCP,
		Metadata:  map[string]string{"route": "helm-mcp-gateway"},
	})
	require.NoError(t, err)
	require.False(t, resp.Allowed)
	require.Equal(t, string(contracts.ReasonPDPError), resp.ReasonCode)

	denyingShim := shim
	denyingShim.Dispatcher = &fakeDispatcher{resp: ToolResponse{Allowed: false, Content: "denied"}}
	resp, err = denyingShim.HandleTool(context.Background(), ToolRequest{
		RequestID: "mcp-deny-default-reason",
		SandboxID: handle.ID,
		Class:     ToolMCP,
		Metadata:  map[string]string{"route": "helm-mcp-gateway"},
	})
	require.NoError(t, err)
	require.False(t, resp.Allowed)
	require.Equal(t, "", resp.ReasonCode)
	require.Equal(t, ReceiptVersionManagedAgentExecution, resp.StructuredContent["managed_agent_receipt_schema"])

	resp, err = shim.HandleTool(context.Background(), ToolRequest{
		RequestID: "unknown-1",
		SandboxID: handle.ID,
		Class:     ToolClass("unknown"),
	})
	require.NoError(t, err)
	require.False(t, resp.Allowed)
	require.Equal(t, string(contracts.ReasonSchemaViolation), resp.ReasonCode)
}

func basicSpec() *actuators.SandboxSpec {
	return &actuators.SandboxSpec{
		Runtime:   "default",
		Resources: actuators.ResourceSpec{MemoryMB: 128, Timeout: time.Second},
		Egress:    actuators.EgressPolicy{Disabled: true},
	}
}

type recordingEgress struct {
	calls int
	rules []actuators.EgressRule
	err   error
}

func (e *recordingEgress) Allow(_ context.Context, _ string, rules []actuators.EgressRule) error {
	e.calls++
	e.rules = append([]actuators.EgressRule(nil), rules...)
	return e.err
}

type failingSigner struct{}

func (failingSigner) Sign([]byte) (string, error) { return "", errors.New("sign failed") }
func (failingSigner) SignerKeyID() string         { return "failing" }

func TestPathAndReceiptHelpers(t *testing.T) {
	require.True(t, withinRoot("/tmp/root", "/tmp/root"))
	require.False(t, withinRoot("/tmp/root", "/tmp/root2/file"))
	require.Equal(t, "/workspace/relative/path", cleanSandboxPath("relative/path"))
	require.Equal(t, "", cleanSandboxPath(" "))
	require.Equal(t, "udp/example.com/53", egressRuleKey(actuators.EgressRule{Host: "example.com", Port: 53, Protocol: "udp"}))
	require.True(t, egressRuleUnrestricted(actuators.EgressRule{Host: "::/0"}))
	require.Equal(t, "MANAGED_AGENT_UNKNOWN", managedEffectType(ToolClass("unknown")))
	require.True(t, strings.HasPrefix(hashAny(map[string]any{"bad": func() {}}), "sha256:"))

	root := t.TempDir()
	target := filepath.Join(root, "target")
	joined, err := safeJoin(target, "nested/file.txt", true)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(joined, target))
}
