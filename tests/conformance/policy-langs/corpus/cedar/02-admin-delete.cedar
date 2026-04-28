permit(
    principal,
    action == Action::"delete",
    resource
)
when { context.role == "admin" };
