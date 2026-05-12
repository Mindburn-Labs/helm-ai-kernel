import type { Story, StoryDefault } from "@ladle/react";
import { useState } from "react";
import {
  AlertDialog,
  Badge,
  Button,
  Combobox,
  DataTable,
  DatePicker,
  Dialog,
  Form,
  FormField,
  FormSummary,
  NumberInput,
  TextInput,
  type ButtonProps,
  type ComboboxOption,
  type DataTableColumn,
} from "@mindburn/ui-core";

export default {
  title: "Primitives",
} satisfies StoryDefault;

/* ── Button ───────────────────────────────────────────────────────────── */

export const ButtonDefault: Story<ButtonProps> = (args) => <Button {...args}>Approve</Button>;
ButtonDefault.args = { variant: "primary", size: "md", disabled: false };
ButtonDefault.argTypes = {
  variant: {
    options: ["primary", "secondary", "ghost", "danger", "approve", "deny", "escalate", "proof", "terminal"],
    control: { type: "select" },
    defaultValue: "primary",
  },
  size: { options: ["sm", "md", "lg"], control: { type: "radio" }, defaultValue: "md" },
  disabled: { control: { type: "boolean" }, defaultValue: false },
};

export const ButtonAsChildLink: Story = () => (
  <Button asChild variant="primary" size="md">
    <a href="#policies">Open policies</a>
  </Button>
);

/* ── Badge ────────────────────────────────────────────────────────────── */

export const BadgeStates: Story = () => (
  <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
    <Badge state="allow" />
    <Badge state="deny" />
    <Badge state="escalate" />
    <Badge state="pending" />
    <Badge state="verified" />
    <Badge state="failed" />
  </div>
);

/* ── Combobox ─────────────────────────────────────────────────────────── */

const policyOptions: readonly ComboboxOption[] = [
  { value: "stripe.allow_v3", label: "stripe.allow_v3", hint: "owner: payments" },
  { value: "stripe.deny_v2", label: "stripe.deny_v2", hint: "owner: risk" },
  { value: "github.escalate_v1", label: "github.escalate_v1", hint: "owner: security" },
  { value: "datadog.alert_v4", label: "datadog.alert_v4", hint: "owner: sre", disabled: true },
];

export const ComboboxDefault: Story = () => (
  <Combobox label="Policy" options={policyOptions} placeholder="Select…" />
);

/* ── DatePicker ───────────────────────────────────────────────────────── */

export const DatePickerDefault: Story = () => {
  const [value, setValue] = useState<Date | null>(new Date());
  return <DatePicker label="Due date" value={value} onValueChange={setValue} />;
};

export const DatePickerWithRange: Story = () => {
  // useState lazy initializer is exempt from `react-hooks/purity` since it
  // runs exactly once on mount. Demo data computed relative to mount time.
  const [{ defaultValue, min, max }] = useState(() => {
    const now = Date.now();
    return {
      defaultValue: new Date(now),
      min: new Date(now - 1000 * 60 * 60 * 24 * 7),
      max: new Date(now + 1000 * 60 * 60 * 24 * 30),
    };
  });
  return <DatePicker label="Window" defaultValue={defaultValue} min={min} max={max} />;
};

/* ── Dialog / AlertDialog ─────────────────────────────────────────────── */

export const DialogConfirmation: Story = () => {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button variant="primary" onClick={() => setOpen(true)}>
        Open dialog
      </Button>
      <Dialog
        open={open}
        title="Confirm rollout"
        description="The change ships to production immediately."
        onClose={() => setOpen(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" onClick={() => setOpen(false)}>
              Roll out
            </Button>
          </>
        }
      >
        <p>Operators will see the new behaviour in under a minute.</p>
      </Dialog>
    </>
  );
};

export const AlertDialogDestructive: Story = () => {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button variant="deny" onClick={() => setOpen(true)}>
        Revoke
      </Button>
      <AlertDialog
        open={open}
        title="Revoke access?"
        description="This cannot be undone."
        confirmLabel="Revoke"
        intent="deny"
        onConfirm={() => setOpen(false)}
        onCancel={() => setOpen(false)}
      />
    </>
  );
};

/* ── Form orchestration ───────────────────────────────────────────────── */

export const FormControlled: Story = () => (
  <Form
    aria-label="Quota form"
    onSubmit={(values) => alert(JSON.stringify(values))}
    validate={(values) => {
      const errors: Record<string, string> = {};
      if (!values.owner) errors.owner = "owner is required";
      const amount = Number(values.amount);
      if (!Number.isFinite(amount) || amount < 0) errors.amount = "amount must be ≥ 0";
      return errors;
    }}
  >
    <div style={{ display: "grid", gap: 12, maxWidth: 360 }}>
      <FormField label="Owner">
        <TextInput name="owner" placeholder="finance-governance" />
      </FormField>
      <FormField label="Amount">
        <NumberInput name="amount" min={0} max={10000} step={10} />
      </FormField>
      <FormSummary />
      <Button type="submit" variant="primary">
        Submit
      </Button>
    </div>
  </Form>
);

/* ── DataTable ────────────────────────────────────────────────────────── */

interface ActionRow {
  readonly id: string;
  readonly action: string;
  readonly env: string;
  readonly verdict: "allow" | "deny" | "escalate";
  readonly amount: number;
}

const sampleRows: readonly ActionRow[] = [
  { id: "1", action: "deploy_production", env: "production", verdict: "escalate", amount: 0 },
  { id: "2", action: "refund_customer", env: "production", verdict: "allow", amount: 250 },
  { id: "3", action: "delete_evidence", env: "staging", verdict: "deny", amount: 0 },
  { id: "4", action: "rotate_credential", env: "production", verdict: "allow", amount: 0 },
  { id: "5", action: "push_artifact", env: "production", verdict: "allow", amount: 0 },
];

const sampleColumns: readonly DataTableColumn<ActionRow>[] = [
  { id: "action", header: "Action", accessor: (r) => r.action, sortable: true, filterable: true, headerLabel: "Action" },
  { id: "env", header: "Environment", accessor: (r) => r.env, sortable: true, filterable: true, headerLabel: "Environment" },
  {
    id: "verdict",
    header: "Verdict",
    accessor: (r) => r.verdict,
    sortable: true,
    headerLabel: "Verdict",
    cell: (row) => <Badge state={row.verdict} />,
  },
  { id: "amount", header: "Amount", accessor: (r) => r.amount, sortable: true, align: "end", headerLabel: "Amount" },
];

export const DataTableDefault: Story = () => (
  <DataTable rows={sampleRows} columns={sampleColumns} getRowId={(r) => r.id} pageSize={10} />
);

export const DataTableMultiSelect: Story = () => (
  <DataTable
    rows={sampleRows}
    columns={sampleColumns}
    getRowId={(r) => r.id}
    selectionMode="multi"
    pageSize={10}
  />
);
