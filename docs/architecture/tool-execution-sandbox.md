---
title: Tool-Execution Sandbox — Scope and Stance
---

# Tool-Execution Sandbox — Scope and Stance

Buyers coming from Microsoft Agent Governance Toolkit or OpenAI Gym-style environments frequently ask: *"Does HELM sandbox the tools it calls?"* This document answers explicitly what HELM does, does not, and will not do with respect to tool execution isolation.

**Summary**: HELM enforces a fail-closed policy boundary before a tool is dispatched and a signed-receipt boundary after the tool returns. HELM does not run the tool inside a sandbox it controls. Tool execution isolation is the caller's responsibility. Adding tool-execution sandboxing is on the roadmap as an *optional*, opt-in layer — not a replacement for the fail-closed boundary that already exists.

## What HELM sandboxes today

| Surface | Sandbox | Where |
|---------|---------|-------|
| Policy evaluation | WASM via [wazero](https://github.com/tetratelabs/wazero) — deterministic, gas-metered, time-bounded | [core/pkg/policy/wasm/](../../core/pkg/policy/wasm/) |
| Skill verification | SkillFortify static analysis proves skills cannot exceed declared capabilities | [core/pkg/pack/verify_capabilities.go](../../core/pkg/pack/verify_capabilities.go) |
| Schema enforcement | JSON Schema validation on every tool call's params, fail-closed on drift | [core/pkg/firewall/firewall.go](../../core/pkg/firewall/firewall.go) |
| Egress | Empty-allowlist-denies firewall with JSON-Schema-pinned tool contracts | [core/pkg/firewall/firewall.go:57](../../core/pkg/firewall/firewall.go) |

All four of these live on the **control** plane — HELM's own decision and data surfaces. None of them sandbox the *execution of the tool itself* (the remote API call, the local subprocess, the filesystem operation).

## What HELM does NOT sandbox today

When a tool call is allowed, HELM dispatches it via the configured `Dispatcher` interface and trusts that the dispatcher is running in an appropriate environment. Specifically, HELM does **not**:

- Launch the tool in a separate OS process.
- Drop capabilities, change UIDs, or apply cgroups.
- Run the tool inside a container, microVM, or Firecracker sandbox.
- Intercept syscalls.
- Apply network namespace isolation to the tool.
- Restrict filesystem access beyond what the connector's own contract pins.

If the tool reads arbitrary files, exfils to arbitrary network destinations, or spawns arbitrary subprocesses, HELM does not stop it once the allow verdict is issued.

## Why this is the design

HELM is an **authority plane**, not a tool runtime. Its job is to decide what is allowed and produce verifiable proof. Building a general-purpose tool sandbox (process isolation, filesystem virtualization, network policies) is a separate, large-surface problem that overlaps heavily with existing OS-level and VM-level solutions (seccomp, AppArmor, gVisor, Firecracker, Kata, WASI). Re-implementing those is out of scope and would increase HELM's TCB significantly.

HELM's approach instead:
1. **Before dispatch**: fail-closed policy gate + schema pinning + threat scanner + budget check.
2. **At dispatch**: signed decision, content-addressed inputs.
3. **After dispatch**: signed receipt, causal DAG node, circuit breaker update.

This covers *authorization*, *intent*, and *evidence*. It does not cover *containment*.

## What buyers coming from AGT should know

Microsoft's Agent Governance Toolkit ships a Python `sandbox.py` using AST/import-hook enforcement. That pattern has known escape paths (ctypes, subprocess, compiled native code) and is specifically Python-runtime-bound. It does not extend to non-Python tool targets. **HELM deliberately does not copy that pattern** — a false sandbox is worse than an honest "containment is out of scope."

If you need tool-execution containment today, layer HELM on top of one of:

| Layer | Tool | What it contains |
|-------|------|------------------|
| OS syscall filter | seccomp-bpf, AppArmor, SELinux | system call surface |
| Container | Docker, Podman, containerd | process + FS + network |
| microVM | Firecracker, Cloud Hypervisor, Kata | kernel surface |
| WebAssembly | wazero, wasmtime (outside HELM policy WASM) | deterministic host bindings |
| Language | Deno, Temporal sandbox | Runtime-specific |

HELM's output is **authoritative about what was allowed and what happened**; these tools are authoritative about **what was structurally possible**. Stack them.

## Roadmap

### Phase 4 option (opt-in)
We are evaluating adding an optional `SandboxDispatcher` that wraps the base dispatcher with a process-level container (runtime-agnostic) or a microVM for high-risk tools. This is **opt-in**, configured at connector registration, and layered *below* the existing firewall. It is not a sandbox bundled into HELM's default binary — it's a contract for plug-in sandbox implementations.

Target interface (exploratory):

```go
type SandboxDispatcher interface {
    Dispatch(ctx context.Context, toolName string, params map[string]any, bounds SandboxBounds) (any, error)
}

type SandboxBounds struct {
    NetworkAllowlist []string
    FilesystemMount  []string
    CPU              time.Duration
    Memory           uint64
    Syscalls         []string
}
```

If built, this will live in `core/pkg/sandbox/` (distinct from `core/pkg/connectors/sandbox/` which is the Daytona/E2B/opensandbox *environment* bridge, not an execution sandbox).

### Explicit non-goals (today)

- Bundling runc/Firecracker into the HELM binary.
- Enforcing tool containment inside HELM's process space (no eBPF, no ptrace, no seccomp filter applied by HELM itself).
- Claiming "sandboxed execution" on the marketing surface until a real implementation ships.

## FAQ

**Q: Does `core/pkg/connectors/sandbox/` sandbox tool execution?**
A: No. That package is a *bridge* between HELM's connector contract and external sandbox *environments* (Daytona, E2B, opensandbox). Those environments do the sandboxing. HELM routes to them; it does not implement containment.

**Q: What about WASM?**
A: `core/pkg/policy/wasm/` sandboxes *policy evaluation*, not tool execution. Running arbitrary tools in WASM is possible in principle but requires every tool to compile to WASI — not practical for REST APIs, subprocesses, or MCP servers.

**Q: Can I put HELM in front of a sandbox and get both?**
A: Yes. That's the recommended architecture: HELM decides, your container/microVM contains. See `examples/sandbox/` (roadmap P1-06 scope) for a reference wiring.

**Q: Does fail-closed enforcement mean a compromised tool can't cause damage?**
A: Fail-closed means undeclared or policy-denied tool calls cannot reach the dispatcher. Once a call is allowed, the tool itself — and the environment it runs in — determines its blast radius. HELM will produce a signed receipt of the damage; it will not prevent it.

## References

- HELM firewall fail-closed enforcement: [core/pkg/firewall/firewall.go](../../core/pkg/firewall/firewall.go)
- Policy WASM runtime: [core/pkg/policy/wasm/](../../core/pkg/policy/wasm/)
- SkillFortify: [core/pkg/pack/verify_capabilities.go](../../core/pkg/pack/verify_capabilities.go)
- OWASP Agentic Top 10 ASI-05 (Code Execution): [docs/security/owasp-agentic-top10-coverage.md](../security/owasp-agentic-top10-coverage.md)
- Three-layer security model: [docs/EXECUTION_SECURITY_MODEL.md](../EXECUTION_SECURITY_MODEL.md)

---

*This document is part of the Phase 0 truth-gate per the [HELM AGT-response roadmap](../../../.claude/plans/helm-agt-response-roadmap.md). Last updated 2026-04-15.*
