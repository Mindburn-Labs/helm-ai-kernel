# i18n Key Namespaces v0

> Authoritative registry of message key namespaces used by TooltipModelV1.
> The VM emits keys; the UI owns translation dictionaries per locale.

## Key Format

`namespace.topic.element` — lowercase, dot-separated, stable.

## Namespaces

| Namespace   | Owner     | Description                    |
| ----------- | --------- | ------------------------------ |
| `tooltip.*` | CPI VM    | Tooltip title and body content |
| `action.*`  | CPI VM    | Action button labels           |
| `reason.*`  | CPI VM    | Reason code human summaries    |
| `status.*`  | Focus API | Agent runtime status labels    |
| `queue.*`   | Focus API | Queue item labels              |

## Reserved Keys (v0)

### Tooltip Keys

| Key                               | Args                                       | Description                    |
| --------------------------------- | ------------------------------------------ | ------------------------------ |
| `tooltip.mica_missing.title`      | `jurisdiction_id`                          | MiCA license requirement title |
| `tooltip.mica_missing.body`       | `jurisdiction_id`, `node_id`               | MiCA detailed explanation      |
| `tooltip.gdpr_shield.title`       | —                                          | GDPR shield requirement title  |
| `tooltip.gdpr_shield.body`        | `node_id`, `data_type`                     | GDPR detailed explanation      |
| `tooltip.budget_exceeded.title`   | `limit_type`                               | Budget limit exceeded title    |
| `tooltip.budget_exceeded.body`    | `current_cents`, `limit_cents`, `currency` | Budget detailed explanation    |
| `tooltip.tool_forbidden.title`    | `tool_id`                                  | Tool not allowed title         |
| `tooltip.approval_required.title` | `action_type`                              | Approval required title        |

### Action Keys

| Key                         | Args               | Description                    |
| --------------------------- | ------------------ | ------------------------------ |
| `action.insert_license`     | `license_type`     | "Add {license_type} license"   |
| `action.insert_transformer` | `transformer_type` | "Insert {transformer_type}"    |
| `action.open_policy_path`   | `policy_path`      | "Edit policy: {policy_path}"   |
| `action.open_prompt_slot`   | `slot`             | "Edit prompt: {slot}"          |
| `action.request_approval`   | `role`             | "Request approval from {role}" |
| `action.view_receipt`       | `receipt_id`       | "View receipt"                 |

## Argument Contracts

- All arg names MUST match the `args` map keys in `Reason` and `MessageRef`
- Financial values: decimal string (not float), e.g. `"500.00"`
- Currency: ISO 4217 code, e.g. `"USD"`
- IDs: opaque strings, never parsed by the translation layer

## Stability

- Keys are stable once shipped (no renames)
- Deprecation: mark in this registry, keep accepting indefinitely
- New keys: append only, never reuse deprecated keys
