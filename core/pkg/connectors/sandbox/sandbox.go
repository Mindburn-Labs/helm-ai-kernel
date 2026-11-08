// Package sandbox is the part the sandbox provider adapters share.
//
// A provider adapter (e2b, daytona, opensandbox, claudemanaged, and the Docker
// provider in core/pkg/sandbox/docker) implements actuators.SandboxActuator.
// helm-gateway needs two things beyond that interface:
//
//   - actuators.Inventory: a read of the provider's own state (one sandbox by
//     id, or the sandboxes that carry given labels), which is how the gateway
//     reconciles an effect whose outcome it could not tell by reading back;
//   - a classified provider call (DoJSON and actuators.CallError), so an
//     adapter can say whether a failed write certainly did not happen.
//
// The seam types live in core/pkg/contracts/actuators, where the gateway's
// adapter reads them without depending on this package; the aliases here are
// what the provider adapters write. Nothing here holds a credential: an adapter
// is built for one operation with the key the gateway's connection custody
// supplied for it (R8).
package sandbox

import (
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

// The seam types, as the provider adapters name them.
type (
	// Info is one sandbox as the provider reports it.
	Info = actuators.Info
	// Inventory is the read side of a provider.
	Inventory = actuators.Inventory
	// Provider is the actuator and its inventory.
	Provider = actuators.Provider
	// CallError is a failed provider call, classified.
	CallError = actuators.CallError
)

const (
	// LabelTenant and LabelAttempt are the labels the gateway puts on every
	// sandbox it creates.
	LabelTenant  = actuators.LabelTenant
	LabelAttempt = actuators.LabelAttempt
	// MaxFound bounds an Inventory.Find answer.
	MaxFound = actuators.MaxFound
)

// ErrBadID is returned for an id ValidID refuses.
var ErrBadID = actuators.ErrBadID

// ValidID reports whether id is a sandbox id an adapter may put in a request
// path or a command line.
func ValidID(id string) bool { return actuators.ValidID(id) }

// AsCallError returns the CallError err wraps, or nil.
func AsCallError(err error) *CallError { return actuators.AsCallError(err) }

// ShellJoin quotes each argument for a POSIX shell and joins them with
// spaces. A provider whose API takes one command string runs the result as
// the original argument vector, whatever the arguments contain.
func ShellJoin(argv []string) string {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}

// UnappliedPolicy refuses a spec that asks for what a provider adapter does
// not apply. An adapter whose provider call carries none of the resource
// limits, the egress policy, the environment or the mounts must not create a
// sandbox for a spec that asks for them: the sandbox would run without the
// limits its permit named and still be reported as created. appliesTimeout is
// whether the adapter sends the spec's timeout. The error wraps
// actuators.ErrNotSupported, so the gateway's dispatch is NOT_SENT.
func UnappliedPolicy(spec *actuators.SandboxSpec, appliesTimeout bool) error {
	if spec == nil {
		return fmt.Errorf("sandbox spec is required")
	}
	var unapplied []string
	add := func(asked bool, name string) {
		if asked {
			unapplied = append(unapplied, name)
		}
	}
	r := spec.Resources
	add(r.CPUMillis != 0, "cpu_millis")
	add(r.MemoryMB != 0, "memory_mb")
	add(r.DiskMB != 0, "disk_mb")
	add(r.MaxProcesses != 0, "max_processes")
	add(!appliesTimeout && r.Timeout != 0, "timeout")
	add(spec.Egress.Disabled, "egress_disabled")
	add(len(spec.Egress.DefaultAllowlist) != 0, "an egress allowlist")
	add(len(spec.Env) != 0, "environment variables")
	add(len(spec.Mounts) != 0, "mounts")
	if len(unapplied) == 0 {
		return nil
	}
	return fmt.Errorf("%w: this provider adapter does not apply %s, and a sandbox is not created without the limits it was asked for",
		actuators.ErrNotSupported, strings.Join(unapplied, ", "))
}
