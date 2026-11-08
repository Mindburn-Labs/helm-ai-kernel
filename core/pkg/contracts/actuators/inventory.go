package actuators

// quantum_posture: this file classifies provider answers and names labels; it
// neither signs nor negotiates a key exchange, and no post-quantum claim is
// made.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

// The labels the gateway puts on every sandbox it creates. The tenant label is
// a digest of the tenant id, so a provider account never learns a tenant id and
// a label value is always label-safe.
const (
	LabelTenant  = "helm.tenant"
	LabelAttempt = "helm.attempt"
)

// Info is one sandbox as the provider reports it.
type Info struct {
	ID     string
	Status SandboxStatus
	Labels map[string]string
	// Runtime is the template or image the provider reports, or "" when it
	// reports none.
	Runtime string
}

// MaxFound bounds an Inventory.Find answer.
const MaxFound = 16

// Inventory is the read side of a sandbox provider: how helm-gateway reads the
// provider's own state back to reconcile an effect whose outcome it could not
// tell.
type Inventory interface {
	// Lookup returns the sandbox, or ErrSandboxNotFound.
	Lookup(ctx context.Context, id string) (*Info, error)
	// Find lists the sandboxes that carry every one of labels. It lists at
	// most MaxFound; a provider that has more answers with an error, never
	// a truncated list.
	Find(ctx context.Context, labels map[string]string) ([]Info, error)
}

// Provider is what the gateway drives: the actuator and its inventory.
type Provider interface {
	SandboxActuator
	Inventory
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidID reports whether id is a sandbox id an adapter may put in a request
// path or a command line: no separator, no escape, no option prefix.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// ErrBadID is returned for an id ValidID refuses.
var ErrBadID = errors.New("sandbox: the sandbox id is not a plain identifier")

// CallError is a failed provider call, classified. A caller that wrote
// something reads Refused to learn whether the write certainly did not happen.
type CallError struct {
	Provider string
	// Status is the HTTP status, or 0 when no answer was read.
	Status int
	// Refused is true when the provider answered with a definite refusal
	// (4xx): a write it refused did not happen. A transport error, a 5xx, an
	// answer too large or unreadable and an answer of the wrong shape are not
	// definite.
	Refused bool
	// Drift is true when the provider answered 2xx but not in the shape the
	// adapter expects (or an answer it cannot read at all).
	Drift bool
	// TooLarge is true when the answer exceeded the limit.
	TooLarge bool
	Detail   string
}

func (e *CallError) Error() string {
	return fmt.Sprintf("%s: %s", e.Provider, e.Detail)
}

// AsCallError returns the CallError err wraps, or nil.
func AsCallError(err error) *CallError {
	var ce *CallError
	if errors.As(err, &ce) {
		return ce
	}
	return nil
}
