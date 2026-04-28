// Example HELM Cedar policy: anyone may view; only admins may delete.
//
// Logical rule expressed identically in:
//   examples/policies/cel/example.cel
//   examples/policies/rego/example.rego
//
// Cedar's entity-shape model means principal/action/resource are EntityUIDs
// of the form Type::"id". Membership in a role is modeled via the
// principal's parent chain in the entities document
// (see examples/policies/cedar/entities.json).

// Anyone may view any resource.
permit(
    principal,
    action == Action::"view",
    resource
);

// Only members of Role::"admin" may delete.
permit(
    principal,
    action == Action::"delete",
    resource
)
when { principal in Role::"admin" };
