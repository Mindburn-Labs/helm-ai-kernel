package rbac

// Built-in roles. These have no TenantID — they serve as templates
// that are applied when binding a principal to a tenant.
var (
	// RoleOwner has full access to all tenant resources.
	RoleOwner = Role{
		RoleID: "owner",
		Name:   "Owner",
		Permissions: []string{
			"workspace:*", "employee:*", "inbox:*", "connector:*",
			"policy:*", "export:*", "tenant:manage",
		},
		IsBuiltin: true,
	}

	// RoleAdmin can manage most resources but not tenant-level settings.
	RoleAdmin = Role{
		RoleID: "admin",
		Name:   "Admin",
		Permissions: []string{
			"workspace:*", "employee:manage", "inbox:*",
			"connector:manage", "policy:read", "export:read",
		},
		IsBuiltin: true,
	}

	// RoleManager can approve inbox items and read most resources.
	RoleManager = Role{
		RoleID: "manager",
		Name:   "Manager",
		Permissions: []string{
			"workspace:read", "employee:read", "inbox:approve",
			"inbox:read", "connector:read",
		},
		IsBuiltin: true,
	}

	// RoleViewer has read-only access.
	RoleViewer = Role{
		RoleID: "viewer",
		Name:   "Viewer",
		Permissions: []string{
			"workspace:read", "employee:read", "inbox:read", "connector:read",
		},
		IsBuiltin: true,
	}
)

// BuiltinRoles returns all built-in role definitions.
func BuiltinRoles() []Role {
	return []Role{RoleOwner, RoleAdmin, RoleManager, RoleViewer}
}
