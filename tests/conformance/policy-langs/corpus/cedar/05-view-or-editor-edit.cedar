permit(
    principal,
    action == Action::"view",
    resource
);

permit(
    principal,
    action == Action::"edit",
    resource
)
when { context.role == "editor" };
