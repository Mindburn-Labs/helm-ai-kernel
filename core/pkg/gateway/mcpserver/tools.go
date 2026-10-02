package mcpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// AttemptGetTool is the one tool that is not an effect: it reads back an
// attempt of the caller's own episode.
const AttemptGetTool = "helm_attempt_get"

// toolNamePattern is what an MCP client and a model API accept as a tool name.
var toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// effectTool is an effect type the gateway performs, offered as a tool.
type effectTool struct {
	Tool
	effectType string
}

// toolName is an effect type's tool name: the dots become underscores, because
// model APIs reject a dot in a function name (github.repository.get is
// github_repository_get).
func toolName(effectType string) string { return strings.ReplaceAll(effectType, ".", "_") }

// effectTools turns the declarations of the gateway's adapters into tools, by
// name. An effect type is offered when a mandate may grant it, it carries an
// argument schema, and it is not a model call, which the model endpoints make
// themselves. An effect type that should be offered and cannot be named is a
// configuration error, like a schema that is not JSON: the gateway refuses to
// start with it, where dropping it silently would leave a seat's tool missing.
func effectTools(all []adapters.Adapter) (map[string]effectTool, error) {
	tools := map[string]effectTool{}
	for _, a := range all {
		for _, d := range a.Declarations() {
			if !d.Grantable || len(d.ArgumentSchema) == 0 || d.EffectType == effectargs.ModelInference {
				continue
			}
			name := toolName(d.EffectType)
			if !toolNamePattern.MatchString(name) {
				return nil, fmt.Errorf("the effect type %q has no valid tool name (%q)", d.EffectType, name)
			}
			if other, taken := tools[name]; taken || name == AttemptGetTool {
				return nil, fmt.Errorf("the effect types %q and %q are both the tool %q", d.EffectType, other.effectType, name)
			}
			schema, err := inputSchema(d)
			if err != nil {
				return nil, fmt.Errorf("the argument schema of %s: %w", d.EffectType, err)
			}
			description := d.Description
			if d.TargetForm != "" {
				description += " Target: " + d.TargetForm + "."
			}
			tools[name] = effectTool{effectType: d.EffectType, Tool: Tool{
				Name: name, Description: strings.TrimSpace(description), InputSchema: schema,
			}}
		}
	}
	return tools, nil
}

// inputSchema is a tool's input: the effect's target, which names what it acts
// on and is never taken from its arguments, and the arguments, under the
// declaration's own closed schema. The embedded schema loses its $schema, $id
// and x-helm: keywords of a document root that a client's validator may not
// accept inside another schema. The gateway validates the arguments against the
// full schema itself, so nothing is enforced here.
func inputSchema(d adapters.Declaration) (json.RawMessage, error) {
	var args map[string]json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(d.ArgumentSchema)).Decode(&args); err != nil || args == nil {
		return nil, fmt.Errorf("not a JSON object: %v", err)
	}
	for _, key := range []string{"$schema", "$id", "x-helm"} {
		delete(args, key)
	}
	target := map[string]any{"type": "string", "minLength": 1, "maxLength": 512}
	if d.TargetForm != "" {
		target["description"] = "What the effect acts on: " + d.TargetForm + "."
	}
	return json.Marshal(map[string]any{
		"type": "object", "additionalProperties": false, "required": []string{"target", "arguments"},
		"properties": map[string]any{"target": target, "arguments": args},
	})
}

// attemptGetTool describes helm_attempt_get.
func attemptGetTool() Tool {
	return Tool{
		Name: AttemptGetTool,
		Description: "Read back an attempt of this episode by its attempt_id: its state, outcome, reason_code and result. " +
			"Use it on a result whose status is \"reconciling\". An attempt of another episode is not found.",
		InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"required":["attempt_id"],` +
			`"properties":{"attempt_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"}}}`),
		Annotations: map[string]any{"readOnlyHint": true, "idempotentHint": true, "openWorldHint": false},
	}
}
