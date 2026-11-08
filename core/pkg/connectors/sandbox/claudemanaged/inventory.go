package claudemanaged

import (
	"context"
	"fmt"
	"sort"

	connsandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

var _ connsandbox.Provider = (*Adapter)(nil)

// Lookup returns the sandbox from the adapter's registry. The registry is the
// provider's state for this adapter: sandboxes are session-scoped, and a
// restart of the process that holds the adapter ends them. A terminated
// sandbox is still reported, with status terminated.
func (a *Adapter) Lookup(_ context.Context, id string) (*connsandbox.Info, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, ok := a.sandboxes[id]
	if !ok {
		return nil, actuators.ErrSandboxNotFound
	}
	return infoOf(state), nil
}

// Find lists the sandboxes that carry every one of labels, ordered by id.
func (a *Adapter) Find(_ context.Context, labels map[string]string) ([]connsandbox.Info, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []connsandbox.Info
	for _, state := range a.sandboxes {
		match := true
		for k, v := range labels {
			if got, ok := state.labels[k]; !ok || got != v {
				match = false
				break
			}
		}
		if match {
			out = append(out, *infoOf(state))
		}
	}
	if len(out) > connsandbox.MaxFound {
		return nil, fmt.Errorf("claude managed agents: more than %d sandboxes match", connsandbox.MaxFound)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// infoOf copies a state's reportable facts. a.mu is held.
func infoOf(state *sandboxState) *connsandbox.Info {
	runtime := ""
	if state.spec != nil {
		runtime = state.spec.Runtime
	}
	return &connsandbox.Info{ID: state.handle.ID, Status: state.handle.Status, Labels: copyStringMap(state.labels), Runtime: runtime}
}
