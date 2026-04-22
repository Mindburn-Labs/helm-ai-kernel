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

The sandbox adapters are resolved through the `SandboxRegistry` (below),
not the `ConnectorRegistry`. The `RunnerBridge` in `bridge.go` provides
backward compatibility with the legacy `sandbox.Runner` interface.

## Provider Matrix

| Package        | Provider             | Stateful          | Egress   |
| -------------- | -------------------- | ----------------- | -------- |
| `opensandbox/` | OpenSandbox REST API | Yes               | Runtime  |
| `e2b/`         | E2B API              | Yes (persistence) | Template |
| `daytona/`     | Daytona SDK API      | No (stateless)    | Config   |

## Usage

```go
import (
    "github.com/Mindburn-Labs/helm-oss/core/pkg/connectors/sandbox/opensandbox"
    "github.com/Mindburn-Labs/helm-oss/core/pkg/connectors/sandbox/e2b"
    "github.com/Mindburn-Labs/helm-oss/core/pkg/connectors/sandbox/daytona"
)

// Pick a provider:
var actuator actuators.SandboxActuator
actuator = opensandbox.New(opensandbox.Config{...})
actuator = e2b.New(e2b.Config{...})
actuator = daytona.New(daytona.Config{...})
```
