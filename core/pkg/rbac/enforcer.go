package rbac

import (
	"context"
	"strings"
	"time"
)

// Enforcer checks permissions against role bindings.
// Fail-closed: any error returns denied.
type Enforcer struct {
	store RBACStore
	clock func() time.Time
}

// NewEnforcer creates a new RBAC enforcer.
func NewEnforcer(store RBACStore) *Enforcer {
	return &Enforcer{store: store, clock: time.Now}
}

// WithClock overrides the clock for deterministic testing.
func (e *Enforcer) WithClock(clock func() time.Time) *Enforcer {
	e.clock = clock
	return e
}

// Check verifies if a principal has a permission in a scope.
// Fail-closed: any error returns denied.
func (e *Enforcer) Check(ctx context.Context, principalID, tenantID, permission, scope string) *AccessDecision {
	decision := &AccessDecision{
		Allowed:    false,
		Permission: permission,
	}

	bindings, err := e.store.ListBindings(ctx, principalID, tenantID)
	if err != nil {
		decision.Reason = "failed to list bindings: " + err.Error()
		return decision
	}

	now := e.clock()

	for _, binding := range bindings {
		// Skip expired bindings.
		if binding.ExpiresAt != nil && now.After(*binding.ExpiresAt) {
			continue
		}

		// Check scope match: "tenant" scope matches everything.
		// Specific scopes like "workspace:ws-1" only match that exact scope.
		if binding.Scope != "tenant" && binding.Scope != scope {
			continue
		}

		role, err := e.store.GetRole(ctx, binding.RoleID)
		if err != nil {
			continue // fail-closed: skip unresolvable roles
		}

		for _, granted := range role.Permissions {
			if MatchPermission(granted, permission) {
				decision.Allowed = true
				decision.RoleID = role.RoleID
				decision.Reason = "permitted by role " + role.Name
				return decision
			}
		}
	}

	decision.Reason = "no matching role binding grants permission " + permission
	return decision
}

// MatchPermission checks if a granted permission matches a required one.
// Supports wildcards: "workspace:*" matches "workspace:read".
// Exact matches are also supported: "inbox:approve" matches "inbox:approve".
func MatchPermission(granted, required string) bool {
	if granted == required {
		return true
	}

	// Wildcard matching: "resource:*" matches "resource:action"
	if strings.HasSuffix(granted, ":*") {
		prefix := strings.TrimSuffix(granted, "*")
		if strings.HasPrefix(required, prefix) {
			return true
		}
	}

	return false
}
