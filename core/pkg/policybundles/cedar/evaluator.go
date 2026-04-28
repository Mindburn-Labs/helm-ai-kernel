package cedar

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	cedar "github.com/cedar-policy/cedar-go"
	cedartypes "github.com/cedar-policy/cedar-go/types"
)

// Evaluator wraps a parsed Cedar policy set and (optional) entity map for
// repeated authorization. The cedar-go Authorize call is read-only, so a
// single Evaluator is safe to share across goroutines.
type Evaluator struct {
	bundle   *CompiledBundle
	policies *cedar.PolicySet
	entities cedar.EntityMap
}

// NewEvaluator parses the persisted policy set and entities document.
// HELM re-parses on load rather than persisting an opaque AST so the
// signed bundle stays human-readable and replayable.
func NewEvaluator(_ context.Context, b *CompiledBundle) (*Evaluator, error) {
	if b == nil {
		return nil, fmt.Errorf("cedar: nil bundle")
	}
	ps, err := parsePolicySet(b.Name, b.PolicySet)
	if err != nil {
		return nil, err
	}
	var entities cedar.EntityMap
	if strings.TrimSpace(b.EntitiesDoc) != "" {
		if err := json.Unmarshal([]byte(b.EntitiesDoc), &entities); err != nil {
			return nil, fmt.Errorf("cedar: parse entities: %w", err)
		}
	}
	return &Evaluator{bundle: b, policies: ps, entities: entities}, nil
}

// Evaluate authorizes the given DecisionRequest. The principal/action/
// resource strings must follow Cedar's "Type::id" UID syntax (e.g.
// `User::"alice"`); when they do not the evaluator wraps them as
// `Principal::<value>` / `Action::<value>` / `Resource::<value>` so that
// Cedar policies can match by id without forcing the caller to hand-craft
// UIDs.
func (e *Evaluator) Evaluate(_ context.Context, req *DecisionRequest) (*Decision, error) {
	if req == nil {
		return nil, fmt.Errorf("cedar: nil request")
	}

	principal, err := toEntityUID("Principal", req.Principal)
	if err != nil {
		return nil, fmt.Errorf("cedar: principal: %w", err)
	}
	action, err := toEntityUID("Action", req.Action)
	if err != nil {
		return nil, fmt.Errorf("cedar: action: %w", err)
	}
	// Tool when set takes precedence over Resource so the same DecisionRequest
	// shape can be reused for tool-call governance without the caller
	// rewriting Resource themselves.
	resourceID := req.Resource
	if req.Tool != "" {
		resourceID = "Tool::\"" + req.Tool + "\""
	}
	resource, err := toEntityUID("Resource", resourceID)
	if err != nil {
		return nil, fmt.Errorf("cedar: resource: %w", err)
	}

	cedarReq := cedar.Request{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   contextRecord(req.Context),
	}

	decision, diag := e.policies.IsAuthorized(e.entities, cedarReq)
	out := &Decision{PolicyID: e.bundle.BundleID}
	if decision == cedartypes.Allow {
		out.Verdict = VerdictAllow
	} else {
		out.Verdict = VerdictDeny
	}
	if len(diag.Reasons) > 0 {
		var ids []string
		for _, r := range diag.Reasons {
			ids = append(ids, string(r.PolicyID))
		}
		out.Reason = "cedar: matched " + strings.Join(ids, ", ")
	} else if out.Verdict == VerdictDeny {
		out.Reason = "cedar: no permit applies"
	}
	if len(diag.Errors) > 0 {
		var msgs []string
		for _, e := range diag.Errors {
			msgs = append(msgs, e.Message)
		}
		// Surface evaluator errors as DENY with an explanation; treating them
		// as ESCALATE would change the semantics of misconfigured policies.
		out.Verdict = VerdictDeny
		out.Reason = "cedar: errors: " + strings.Join(msgs, "; ")
	}
	return out, nil
}

// toEntityUID parses a Cedar UID like `User::"alice"`. If the value is a
// bare identifier (e.g. "alice") it is wrapped as `<defaultType>::"alice"`.
func toEntityUID(defaultType, value string) (cedartypes.EntityUID, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return cedartypes.EntityUID{}, fmt.Errorf("empty UID")
	}
	if strings.Contains(v, "::") {
		idx := strings.Index(v, "::")
		typ := strings.TrimSpace(v[:idx])
		idPart := strings.TrimSpace(v[idx+2:])
		idPart = strings.Trim(idPart, "\"")
		if typ == "" || idPart == "" {
			return cedartypes.EntityUID{}, fmt.Errorf("malformed UID %q", v)
		}
		return cedar.NewEntityUID(cedartypes.EntityType(typ), cedartypes.String(idPart)), nil
	}
	return cedar.NewEntityUID(cedartypes.EntityType(defaultType), cedartypes.String(v)), nil
}

// contextRecord converts a Go map into a Cedar Record. Unsupported types
// fall through as Cedar strings so policies can still match on them.
func contextRecord(in map[string]interface{}) cedartypes.Record {
	if len(in) == 0 {
		return cedartypes.NewRecord(cedartypes.RecordMap{})
	}
	rm := make(cedartypes.RecordMap, len(in))
	for k, raw := range in {
		rm[cedartypes.String(k)] = toCedarValue(raw)
	}
	return cedartypes.NewRecord(rm)
}

// toCedarValue maps Go scalars to Cedar's value types. Everything else
// degrades to its fmt.Sprint string form so the evaluator never panics
// on caller-supplied context maps.
func toCedarValue(raw interface{}) cedartypes.Value {
	switch v := raw.(type) {
	case nil:
		return cedartypes.String("")
	case bool:
		return cedartypes.Boolean(v)
	case int:
		return cedartypes.Long(v)
	case int32:
		return cedartypes.Long(v)
	case int64:
		return cedartypes.Long(v)
	case float64:
		return cedartypes.Long(int64(v))
	case string:
		return cedartypes.String(v)
	case []interface{}:
		members := make([]cedartypes.Value, 0, len(v))
		for _, m := range v {
			members = append(members, toCedarValue(m))
		}
		return cedartypes.NewSet(members...)
	default:
		return cedartypes.String(fmt.Sprintf("%v", v))
	}
}
