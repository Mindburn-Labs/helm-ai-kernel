# Sandbox Provider Connector Definitions

This package (`core/pkg/connectors/sandbox/`) contains the `SandboxActuator`
adapter implementations for external sandbox providers.

## Relationship to ConnectorRegistry

The sandbox adapters implement `actuators.SandboxActuator` — a specialized
interface for sandbox lifecycle management, execution, and governance.
This is intentionally _separate_ from the `connectors.Connector` interface
because sandbox management is fundamentally different from REST-based tool
connectors:

- **Connector** = ID + Capabilities + Execute (single request/response)
- **SandboxActuator** = Lifecycle + Exec + Filesystem + Network + Observability

Each adapter also implements `actuators.Inventory` (`Lookup`, `Find`): a read
of the provider's own state by sandbox id or by label. `helm-gateway` drives
the adapters through `actuators.Provider` (actuator plus inventory) as the
sandbox effects `sandbox.create`, `sandbox.exec` and `sandbox.terminate`; see
"Sandbox effects (P17)" in `docs/architecture/gateway-effect-api.md`. The
shared pieces here are `DoJSON` (a bounded, classified provider call that never
follows a redirect), `ShellJoin` and `ValidID`. The legacy `RunnerBridge` and
the `BranchFS` placeholder were removed: nothing called them.

## Provider Matrix

| Package        | Provider             | Stateful          | Egress   |
| -------------- | -------------------- | ----------------- | -------- |
| `opensandbox/` | OpenSandbox REST API | Yes               | Runtime  |
| `e2b/`         | E2B API              | Yes (persistence) | Template |
| `daytona/`     | Daytona SDK API      | No (stateless)    | Config   |
| `claudemanaged/` | Claude Managed Agents self-hosted worker | No (session-scoped) | HELM grant + worker/VPC |

## Usage

```go
import (
    "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox/opensandbox"
    "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox/e2b"
    "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox/daytona"
    "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox/claudemanaged"
)

// Pick a provider:
var actuator actuators.SandboxActuator
actuator = opensandbox.New(opensandbox.Config{...})
actuator = e2b.New(e2b.Config{...})
actuator = daytona.New(daytona.Config{...})
actuator = claudemanaged.New(claudemanaged.Config{...})
```
