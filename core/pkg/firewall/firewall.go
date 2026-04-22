package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// Dispatcher executes the actual tool logic.
type Dispatcher interface {
	Dispatch(ctx context.Context, toolName string, params map[string]any) (any, error)
}

// PolicyFirewall enforces strict governance on tool execution.
type PolicyFirewall struct {
	allowedTools map[string]bool
	schema       map[string]*jsonschema.Schema // tool -> compiled JSON Schema for params
	next         Dispatcher
}

// NewPolicyFirewall creates a firewall with a strict allowlist.
func NewPolicyFirewall(next Dispatcher) *PolicyFirewall {
	return &PolicyFirewall{
		allowedTools: make(map[string]bool),
		schema:       make(map[string]*jsonschema.Schema),
		next:         next,
	}
}

// Allow tool adds a tool to the whitelist.
func (f *PolicyFirewall) AllowTool(name string, schema string) error {
	f.allowedTools[name] = true
	if schema == "" {
		delete(f.schema, name)
		return nil
	}

	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft2020
	schemaURL := fmt.Sprintf("https://helm.schemas.local/firewall/%s.schema.json", name)
	if err := c.AddResource(schemaURL, strings.NewReader(schema)); err != nil {
		return fmt.Errorf("firewall schema load failed: %w", err)
	}
	compiled, err := c.Compile(schemaURL)
	if err != nil {
		return fmt.Errorf("firewall schema compile failed: %w", err)
	}
	f.schema[name] = compiled
	return nil
}

// CallTool executes a tool call if policy allows.
func (f *PolicyFirewall) CallTool(ctx context.Context, bundle PolicyInputBundle, toolName string, params map[string]any) (any, error) {
	// 1. Check Allowlist
	if !f.allowedTools[toolName] {
		return nil, fmt.Errorf("firewall blocked tool %q: not in allowlist", toolName)
	}

	// 2. Validate Params Against Schema (if configured)
	if schema, ok := f.schema[toolName]; ok && schema != nil {
		if params == nil {
			return nil, fmt.Errorf("firewall blocked tool %q: missing parameters", toolName)
		}
		if err := schema.Validate(params); err != nil {
			return nil, fmt.Errorf("firewall blocked tool %q: schema validation failed: %w", toolName, err)
		}
	}

	// 3. Delegate to Next (required)
	if f.next == nil {
		return nil, fmt.Errorf("firewall dispatcher not configured (fail-closed)")
	}
	return f.next.Dispatch(ctx, toolName, params)
}

// PolicyInputBundle contains context for policy decisions.
type PolicyInputBundle struct {
	ActorID   string
	Role      string
	SessionID string
}
