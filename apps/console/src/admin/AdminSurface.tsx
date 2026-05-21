import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { AlertCircle, CheckCircle2, RefreshCw } from "lucide-react";
import { isUnauthorizedError, type AdminRecord, type AdminResult } from "../api/client";
import type {
  AdminActionConfig,
  AdminActionValues,
  AdminColumnConfig,
  AdminFieldConfig,
  AdminSurfaceConfig,
} from "./surfaces";

interface AdminSurfaceProps {
  readonly config: AdminSurfaceConfig;
  readonly authRevision: number;
}

export function AdminSurface({ config, authRevision }: AdminSurfaceProps) {
  const [data, setData] = useState<AdminResult>(undefined);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [selectedIndex, setSelectedIndex] = useState(0);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const next = await config.read();
      setData(next);
      setSelectedIndex(0);
    } catch (err) {
      setData(undefined);
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }, [config]);

  useEffect(() => {
    void refresh();
  }, [refresh, authRevision]);

  const rows = useMemo(() => config.rows(data), [config, data]);
  const selected = rows[selectedIndex] ?? null;

  return (
    <section className="admin-surface" data-surface-id={config.id}>
      <header className="admin-surface__header">
        <div>
          <p className="surface-kicker">{config.eyebrow}</p>
          <h2>{config.title}</h2>
          <p>{config.body}</p>
        </div>
        <div className="admin-source">
          <span>Source</span>
          <strong>{config.source}</strong>
          <button className="admin-icon-button" type="button" onClick={() => void refresh()} aria-label={`Refresh ${config.title}`}>
            <RefreshCw size={16} aria-hidden />
          </button>
        </div>
      </header>

      {config.actions?.length ? (
        <AdminActionGrid actions={config.actions} onRefresh={refresh} />
      ) : null}

      <div className="admin-grid">
        <div className="admin-table-panel">
          {loading ? (
            <AdminState title="Loading surface" body={`Reading ${config.source}.`} />
          ) : error ? (
            <AdminState
              tone="error"
              title={isUnauthorizedError(error) ? "Admin access required" : "Surface unavailable"}
              body={isUnauthorizedError(error) ? "Provide a valid admin key and tenant ID, then refresh this surface." : error.message}
            />
          ) : rows.length === 0 ? (
            <AdminState title={config.emptyTitle} body={config.emptyBody} />
          ) : (
            <AdminDataTable
              columns={config.columns}
              rows={rows}
              selectedIndex={selectedIndex}
              onSelect={setSelectedIndex}
              label={config.title}
            />
          )}
        </div>

        <details className="admin-detail-panel" aria-label={`${config.detailTitle} detail`}>
          <summary className="admin-detail-panel__header">
            <span>{config.detailTitle}</span>
            <strong>{selected ? recordLabel(selected, config.columns) : "No selection"}</strong>
          </summary>
          <pre>{JSON.stringify(selected ?? data ?? {}, null, 2)}</pre>
        </details>
      </div>
    </section>
  );
}

interface AdminActionGridProps {
  readonly actions: readonly AdminActionConfig[];
  readonly onRefresh: () => Promise<void>;
}

function AdminActionGrid({ actions, onRefresh }: AdminActionGridProps) {
  const [activeActionId, setActiveActionId] = useState(actions[0]?.id ?? "");

  useEffect(() => {
    if (!actions.some((action) => action.id === activeActionId)) {
      setActiveActionId(actions[0]?.id ?? "");
    }
  }, [actions, activeActionId]);

  const activeAction = actions.find((action) => action.id === activeActionId) ?? actions[0];

  return (
    <section className="admin-actions" aria-label="Admin actions">
      <div className="admin-action-strip" role="toolbar" aria-label="Available actions">
        {actions.map((action) => (
          <button
            key={action.id}
            type="button"
            className={action.id === activeAction?.id ? "admin-action-choice is-active" : "admin-action-choice"}
            aria-pressed={action.id === activeAction?.id}
            onClick={() => setActiveActionId(action.id)}
          >
            {action.label}
          </button>
        ))}
      </div>
      {activeAction ? <AdminActionCard key={activeAction.id} action={activeAction} onRefresh={onRefresh} /> : null}
    </section>
  );
}

interface AdminActionCardProps {
  readonly action: AdminActionConfig;
  readonly onRefresh: () => Promise<void>;
}

function AdminActionCard({ action, onRefresh }: AdminActionCardProps) {
  const initialValues = useMemo(() => initialActionValues(action.fields ?? []), [action.fields]);
  const [values, setValues] = useState<AdminActionValues>(initialValues);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<AdminResult>(null);
  const [error, setError] = useState<Error | null>(null);

  const updateValue = (field: AdminFieldConfig, value: string) => {
    setValues((current) => ({ ...current, [field.id]: value }));
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (action.disabledReason) return;
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      const next = await action.run(values);
      setResult(next ?? { ok: true });
      if (action.refreshAfter) {
        await onRefresh();
      }
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setRunning(false);
    }
  };

  return (
    <form className="admin-action-card" onSubmit={(event) => void submit(event)}>
      <div className="admin-action-card__header">
        <strong>{action.label}</strong>
        <span>{action.description}</span>
      </div>
      {action.disabledReason ? (
        <p className="admin-action-card__disabled">{action.disabledReason}</p>
      ) : null}
      {(action.fields ?? []).map((field) => (
        <label className="admin-field" key={field.id}>
          <span>
            {field.label}
            {field.required ? " *" : ""}
          </span>
          {field.kind === "textarea" ? (
            <textarea
              value={values[field.id] ?? ""}
              placeholder={field.placeholder}
              required={field.required}
              onChange={(event) => updateValue(field, event.target.value)}
            />
          ) : field.kind === "select" ? (
            <select
              value={values[field.id] ?? ""}
              required={field.required}
              onChange={(event) => updateValue(field, event.target.value)}
            >
              {(field.options ?? []).map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          ) : (
            <input
              value={values[field.id] ?? ""}
              placeholder={field.placeholder}
              required={field.required}
              onChange={(event) => updateValue(field, event.target.value)}
            />
          )}
        </label>
      ))}
      <button className="admin-action-button" type="submit" disabled={running || Boolean(action.disabledReason)}>
        {running ? "Running" : `Run ${action.label}`}
      </button>
      {error ? (
        <div className="admin-action-result admin-action-result--error" role="alert">
          <AlertCircle size={16} aria-hidden />
          <span>{error.message}</span>
        </div>
      ) : null}
      {result !== null ? (
        <div className="admin-action-result">
          <CheckCircle2 size={16} aria-hidden />
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </div>
      ) : null}
    </form>
  );
}

interface AdminDataTableProps {
  readonly columns: readonly AdminColumnConfig[];
  readonly rows: readonly AdminRecord[];
  readonly selectedIndex: number;
  readonly onSelect: (index: number) => void;
  readonly label: string;
}

function AdminDataTable({ columns, rows, selectedIndex, onSelect, label }: AdminDataTableProps) {
  return (
    <div className="admin-table-wrap">
      <table className="admin-table" aria-label={label}>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key} data-priority={column.priority ?? "secondary"}>
                {column.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={`${recordLabel(row, columns)}-${index}`} data-selected={index === selectedIndex}>
              {columns.map((column, columnIndex) => (
                <td key={column.key} data-label={column.label} data-priority={column.priority ?? "secondary"}>
                  {columnIndex === 0 ? (
                    <button className="admin-row-button" type="button" onClick={() => onSelect(index)}>
                      {formatValue(row[column.key])}
                    </button>
                  ) : (
                    formatValue(row[column.key])
                  )}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

interface AdminStateProps {
  readonly title: string;
  readonly body: string;
  readonly tone?: "neutral" | "error";
}

function AdminState({ title, body, tone = "neutral" }: AdminStateProps) {
  return (
    <div className="admin-state" data-tone={tone}>
      <strong>{title}</strong>
      <p>{body}</p>
    </div>
  );
}

function initialActionValues(fields: readonly AdminFieldConfig[]): AdminActionValues {
  return Object.fromEntries(
    fields.map((field) => [field.id, field.defaultValue ?? field.options?.[0] ?? ""]),
  );
}

function formatValue(value: unknown): string {
  if (value === undefined || value === null || value === "") return "none";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(formatValue).join(", ");
  return JSON.stringify(value);
}

function recordLabel(row: AdminRecord, columns: readonly AdminColumnConfig[]): string {
  const firstPrimary = columns.find((column) => column.priority === "primary") ?? columns[0];
  return firstPrimary ? formatValue(row[firstPrimary.key]) : "record";
}
