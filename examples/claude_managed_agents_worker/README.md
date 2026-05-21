# Claude Managed Agents Worker Shim

This example shows the intended integration shape for Anthropic Managed Agents
self-hosted workers: Anthropic owns orchestration; HELM owns local execution
authority.

```go
cfg := claudemanaged.DefaultConfig()
cfg.WorkerID = "worker-prod-us-1"
cfg.WorkerImageDigest = "sha256:<pinned image digest>"
cfg.SkillManifestHash = "sha256:<downloaded skills manifest hash>"
cfg.EnvironmentKeyConfigured = true
cfg.EnvironmentKeyFromSecretStore = true
cfg.LogRetentionEnabled = true

adapter := claudemanaged.New(cfg)
handle, _ := adapter.Create(ctx, &actuators.SandboxSpec{
    Runtime: "claude-managed-worker",
    Egress: actuators.EgressPolicy{Disabled: true},
})

shim := claudemanaged.WorkerShim{Actuator: adapter}
resp, _ := shim.HandleTool(ctx, claudemanaged.ToolRequest{
    RequestID: "tool-call-1",
    SandboxID: handle.ID,
    Class:     claudemanaged.ToolBash,
    Command:   []string{"echo", "hello"},
})
_ = resp.ReceiptID
```

MCP tools should be exposed to Claude through the Anthropic tunnel only when the
tunnel routes to HELM MCP Gateway. The gateway then performs schema pinning,
OAuth scope checks, quarantine/rugpull checks, and receipt binding before any
upstream MCP tool dispatch.
