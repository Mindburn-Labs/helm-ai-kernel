package command

import (
	"context"
	"errors"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/experimental/mama/runtime"
)

// Command represents a high-level intent parsed from the UI or scheduler.
type Command interface {
	Name() string
	Execute(ctx context.Context, mission *runtime.MissionState) error
}

// Registry holds the canonical set of valid MAMA actions.
type Registry struct {
	commands map[string]Command
}

// NewRegistry creates a new command registry.
func NewRegistry() *Registry {
	return &Registry{
		commands: make(map[string]Command),
	}
}

// CanonicalCommands defines the exact CLI surface permitted by the MAMA standard.
var CanonicalCommands = map[string]bool{
	"mission": true, "memory": true, "mode": true, "agents": true, "skill": true,
	"env": true, "episode": true, "replay": true, "bench": true, "loop": true,
	"promote": true, "rewind": true, "branch": true, "compact": true,
	"permissions": true, "proof": true,
}

// Register enforces that only strict, reviewable commands are bound to MAMA.
func (r *Registry) Register(cmd Command) error {
	if !CanonicalCommands[cmd.Name()] {
		return errors.New("canonical violation: attempt to register non-standard MAMA command")
	}
	r.commands[cmd.Name()] = cmd
	return nil
}

// Dispatch executes the command and ensures the mission state boundaries are maintained.
func (r *Registry) Dispatch(ctx context.Context, name string, mission *runtime.MissionState) error {
	cmd, exists := r.commands[name]
	if !exists {
		return errors.New("forbidden command: bypassing canonical registry")
	}

	return cmd.Execute(ctx, mission)
}
