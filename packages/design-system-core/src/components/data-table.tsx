"use client";

import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

const VIRTUAL_INITIAL_WINDOW = 100;
const VIRTUAL_INCREMENT = 100;
import { ChevronDown, ChevronsUpDown, ChevronUp } from "lucide-react";
import { EmptyState, Pagination } from "./core";
import type { Density } from "../state/semantics";

/**
 * Generic, headless-style `DataTable<TRow>` and `useDataTable<TRow>` —
 * sort, filter, pagination, selection, column visibility, density. Pairs
 * with the existing `<Pagination>` primitive at the footer and `<EmptyState>`
 * when the filtered set is empty.
 *
 * The HELM-specific `ActionRecordTable` does NOT use this primitive yet —
 * a jscodeshift migration is queued (see ROADMAP). The migration path:
 * each existing column becomes a `DataTableColumn<ActionRecord>` with a
 * `cell` renderer that wraps the existing badges and HashText. With
 * `virtualize` now implemented (sentinel-row IntersectionObserver +
 * 100-row windowing), the legacy table's bespoke windowing can be
 * replaced 1:1 by `<DataTable virtualize pageSize={0}>`.
 *
 * CSS uses the `.dt-*` prefix to avoid collision with the existing
 * `.data-table` element class on the legacy table.
 */

export type SortDirection = "asc" | "desc";

export interface SortState {
  readonly columnId: string;
  readonly direction: SortDirection;
}

export type FilterState = Readonly<Record<string, string>>;

export interface CellCtx {
  readonly rowIndex: number;
  readonly absoluteIndex: number;
  readonly density: Density;
  readonly selected: boolean;
}

export interface DataTableColumn<TRow> {
  readonly id: string;
  readonly header: ReactNode;
  readonly accessor: (row: TRow) => unknown;
  readonly cell?: (row: TRow, ctx: CellCtx) => ReactNode;
  readonly align?: "start" | "end" | "center";
  readonly width?: string | number;
  readonly sortable?: boolean;
  readonly filterable?: boolean;
  readonly hidden?: boolean;
  readonly stickyLeading?: boolean;
  readonly compare?: (a: TRow, b: TRow) => number;
  readonly headerLabel?: string;
}

export type SelectionMode = "none" | "single" | "multi";

export interface DataTableConfig<TRow> {
  readonly rows: readonly TRow[];
  readonly columns: readonly DataTableColumn<TRow>[];
  readonly getRowId: (row: TRow) => string;

  readonly sort?: SortState | null;
  readonly defaultSort?: SortState | null;
  readonly onSortChange?: (sort: SortState | null) => void;

  readonly filter?: FilterState;
  readonly defaultFilter?: FilterState;
  readonly onFilterChange?: (filter: FilterState) => void;

  readonly page?: number;
  readonly defaultPage?: number;
  readonly onPageChange?: (page: number) => void;
  /** Page size; `0` disables pagination (renders all rows). Default 25. */
  readonly pageSize?: number;

  readonly selectionMode?: SelectionMode;
  readonly selection?: ReadonlySet<string>;
  readonly defaultSelection?: ReadonlySet<string>;
  readonly onSelectionChange?: (sel: ReadonlySet<string>) => void;

  readonly columnVisibility?: Readonly<Record<string, boolean>>;
  readonly defaultColumnVisibility?: Readonly<Record<string, boolean>>;
  readonly onColumnVisibilityChange?: (vis: Record<string, boolean>) => void;
}

export interface UseDataTableResult<TRow> {
  readonly rows: readonly TRow[];
  readonly allFiltered: readonly TRow[];
  readonly columns: readonly DataTableColumn<TRow>[];

  readonly sort: SortState | null;
  readonly setSort: (s: SortState | null) => void;
  readonly cycleSort: (columnId: string) => void;

  readonly filter: FilterState;
  readonly setFilter: (f: FilterState) => void;
  readonly setColumnFilter: (columnId: string, value: string) => void;

  readonly page: number;
  readonly pageCount: number;
  readonly pageSize: number;
  readonly setPage: (p: number) => void;

  readonly selection: ReadonlySet<string>;
  readonly setSelection: (s: ReadonlySet<string>) => void;
  readonly toggleRow: (id: string) => void;
  readonly toggleAllOnPage: () => void;

  readonly columnVisibility: Readonly<Record<string, boolean>>;
  readonly setColumnVisibility: (vis: Record<string, boolean>) => void;
  readonly toggleColumn: (id: string) => void;
}

function defaultCompare(a: unknown, b: unknown): number {
  if (a == null && b == null) return 0;
  if (a == null) return -1;
  if (b == null) return 1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  if (a instanceof Date && b instanceof Date) return a.getTime() - b.getTime();
  if (typeof a === "boolean" && typeof b === "boolean") return Number(a) - Number(b);
  return String(a).localeCompare(String(b));
}

function useControlled<T>(controlled: T | undefined, fallback: T) {
  const [internal, setInternal] = useState<T>(controlled !== undefined ? controlled : fallback);
  const isControlled = controlled !== undefined;
  const value = isControlled ? (controlled as T) : internal;
  const setValue = useCallback(
    (next: T) => {
      if (!isControlled) setInternal(next);
    },
    [isControlled],
  );
  return [value, setValue, isControlled] as const;
}

export function useDataTable<TRow>(config: DataTableConfig<TRow>): UseDataTableResult<TRow> {
  const {
    rows,
    columns,
    getRowId,
    sort: sortProp,
    defaultSort,
    onSortChange,
    filter: filterProp,
    defaultFilter,
    onFilterChange,
    page: pageProp,
    defaultPage,
    onPageChange,
    pageSize = 25,
    selectionMode = "none",
    selection: selectionProp,
    defaultSelection,
    onSelectionChange,
    columnVisibility: visibilityProp,
    defaultColumnVisibility,
    onColumnVisibilityChange,
  } = config;

  const initialVisibility = useMemo(() => {
    if (visibilityProp ?? defaultColumnVisibility) return undefined;
    const seed: Record<string, boolean> = {};
    for (const col of columns) seed[col.id] = !col.hidden;
    return seed;
  }, [columns, defaultColumnVisibility, visibilityProp]);

  const [sort, setSortState, sortControlled] = useControlled<SortState | null>(sortProp, defaultSort ?? null);
  const setSort = useCallback(
    (next: SortState | null) => {
      if (!sortControlled) setSortState(next);
      onSortChange?.(next);
    },
    [setSortState, sortControlled, onSortChange],
  );

  const [filter, setFilterState, filterControlled] = useControlled<FilterState>(filterProp, defaultFilter ?? {});
  const setFilter = useCallback(
    (next: FilterState) => {
      if (!filterControlled) setFilterState(next);
      onFilterChange?.(next);
    },
    [setFilterState, filterControlled, onFilterChange],
  );
  const setColumnFilter = useCallback(
    (columnId: string, value: string) => {
      const next = { ...filter, [columnId]: value };
      if (!value) delete next[columnId];
      setFilter(next);
    },
    [filter, setFilter],
  );

  const [page, setPageState, pageControlled] = useControlled<number>(pageProp, defaultPage ?? 1);
  const setPage = useCallback(
    (next: number) => {
      if (!pageControlled) setPageState(next);
      onPageChange?.(next);
    },
    [setPageState, pageControlled, onPageChange],
  );

  const [selection, setSelectionState, selectionControlled] = useControlled<ReadonlySet<string>>(
    selectionProp,
    defaultSelection ?? new Set<string>(),
  );
  const setSelection = useCallback(
    (next: ReadonlySet<string>) => {
      if (!selectionControlled) setSelectionState(next);
      onSelectionChange?.(next);
    },
    [setSelectionState, selectionControlled, onSelectionChange],
  );
  const toggleRow = useCallback(
    (id: string) => {
      const next = new Set(selection);
      if (next.has(id)) {
        next.delete(id);
      } else {
        if (selectionMode === "single") next.clear();
        next.add(id);
      }
      setSelection(next);
    },
    [selection, selectionMode, setSelection],
  );

  const [columnVisibility, setColumnVisibilityState, visibilityControlled] = useControlled<Readonly<Record<string, boolean>>>(
    visibilityProp,
    defaultColumnVisibility ?? initialVisibility ?? {},
  );
  const setColumnVisibility = useCallback(
    (next: Record<string, boolean>) => {
      if (!visibilityControlled) setColumnVisibilityState(next);
      onColumnVisibilityChange?.(next);
    },
    [setColumnVisibilityState, visibilityControlled, onColumnVisibilityChange],
  );
  const toggleColumn = useCallback(
    (id: string) => {
      const next = { ...columnVisibility, [id]: columnVisibility[id] === false ? true : false };
      setColumnVisibility(next);
    },
    [columnVisibility, setColumnVisibility],
  );

  const visibleColumns = useMemo(
    () => columns.filter((c) => columnVisibility[c.id] !== false && !c.hidden),
    [columns, columnVisibility],
  );

  const filtered = useMemo(() => {
    const entries = Object.entries(filter).filter(([, v]) => v !== undefined && v !== "");
    if (entries.length === 0) return rows;
    return rows.filter((row) =>
      entries.every(([colId, needle]) => {
        const col = columns.find((c) => c.id === colId);
        if (!col || !col.filterable) return true;
        return String(col.accessor(row) ?? "").toLowerCase().includes(needle.toLowerCase());
      }),
    );
  }, [rows, filter, columns]);

  const sorted = useMemo(() => {
    if (!sort) return filtered;
    const col = columns.find((c) => c.id === sort.columnId);
    if (!col || col.sortable === false) return filtered;
    const compare = col.compare ?? ((a: TRow, b: TRow) => defaultCompare(col.accessor(a), col.accessor(b)));
    const indexed = filtered.map((row, index) => ({ row, index }));
    indexed.sort((a, b) => {
      const cmp = compare(a.row, b.row);
      return cmp === 0 ? a.index - b.index : sort.direction === "asc" ? cmp : -cmp;
    });
    return indexed.map((entry) => entry.row);
  }, [filtered, sort, columns]);

  const effectivePageSize = pageSize > 0 ? pageSize : sorted.length || 1;
  const pageCount = pageSize > 0 ? Math.max(1, Math.ceil(sorted.length / effectivePageSize)) : 1;
  const clampedPage = Math.min(Math.max(1, page), pageCount);
  const pagedRows = pageSize > 0
    ? sorted.slice((clampedPage - 1) * effectivePageSize, clampedPage * effectivePageSize)
    : sorted;

  const cycleSort = useCallback(
    (columnId: string) => {
      const col = columns.find((c) => c.id === columnId);
      if (!col || col.sortable === false) return;
      if (!sort || sort.columnId !== columnId) {
        setSort({ columnId, direction: "asc" });
      } else if (sort.direction === "asc") {
        setSort({ columnId, direction: "desc" });
      } else {
        setSort(null);
      }
    },
    [columns, sort, setSort],
  );

  const toggleAllOnPage = useCallback(() => {
    const ids = pagedRows.map(getRowId);
    const allSelected = ids.every((id) => selection.has(id));
    const next = new Set(selection);
    if (allSelected) ids.forEach((id) => next.delete(id));
    else ids.forEach((id) => next.add(id));
    setSelection(next);
  }, [pagedRows, getRowId, selection, setSelection]);

  return {
    rows: pagedRows,
    allFiltered: sorted,
    columns: visibleColumns,
    sort,
    setSort,
    cycleSort,
    filter,
    setFilter,
    setColumnFilter,
    page: clampedPage,
    pageCount,
    pageSize: effectivePageSize,
    setPage,
    selection,
    setSelection,
    toggleRow,
    toggleAllOnPage,
    columnVisibility,
    setColumnVisibility,
    toggleColumn,
  };
}

export interface DataTableProps<TRow> extends DataTableConfig<TRow> {
  readonly caption?: string;
  readonly density?: Density;
  /**
   * Enable IntersectionObserver-based row windowing. When combined with
   * `pageSize=0` (pagination disabled), the DOM contains the first 100
   * rows and grows in 100-row increments as a sentinel row scrolls into
   * view. `aria-rowcount` always reflects the full filtered count so AT
   * users see the real total even though the DOM is windowed.
   */
  readonly virtualize?: boolean;
  readonly emptyTitle?: string;
  readonly emptyBody?: string;
  readonly emptyAction?: ReactNode;
  readonly onRowActivate?: (row: TRow) => void;
  readonly className?: string;
  readonly toolbar?: ReactNode;
}

function SortIndicator({ state }: { state: SortDirection | null }) {
  if (state === "asc") return <ChevronUp size={12} aria-hidden="true" />;
  if (state === "desc") return <ChevronDown size={12} aria-hidden="true" />;
  return <ChevronsUpDown size={12} aria-hidden="true" />;
}

export function DataTable<TRow>({
  caption,
  density = "compact",
  virtualize = false,
  emptyTitle = "No matching rows",
  emptyBody = "Adjust filters to see more.",
  emptyAction,
  onRowActivate,
  className,
  toolbar,
  ...config
}: DataTableProps<TRow>) {
  const table = useDataTable(config);
  const captionId = useId();
  const hasSelection = (config.selectionMode ?? "none") !== "none";
  const colSpan = table.columns.length + (hasSelection ? 1 : 0);

  const sentinelRef = useRef<HTMLTableRowElement | null>(null);
  const [windowSize, setWindowSize] = useState(VIRTUAL_INITIAL_WINDOW);
  const useVirtualWindow = virtualize && (config.pageSize ?? 25) === 0;
  const visibleRows = useVirtualWindow
    ? table.allFiltered.slice(0, windowSize)
    : table.rows;
  const showSentinel = useVirtualWindow && visibleRows.length < table.allFiltered.length;

  useEffect(() => {
    if (!useVirtualWindow) return undefined;
    const node = sentinelRef.current;
    if (!node) return undefined;
    if (typeof IntersectionObserver === "undefined") return undefined;
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setWindowSize((current) => current + VIRTUAL_INCREMENT);
          }
        }
      },
      { rootMargin: "200px" },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [useVirtualWindow, table.allFiltered.length, visibleRows.length]);


  return (
    <div className={["dt-frame", className].filter(Boolean).join(" ")} data-density={density}>
      {toolbar ? <div className="dt-toolbar">{toolbar}</div> : null}
      <table
        className="dt"
        role="table"
        aria-rowcount={table.allFiltered.length + 1}
        aria-colcount={colSpan}
        aria-multiselectable={config.selectionMode === "multi" || undefined}
        aria-describedby={caption ? captionId : undefined}
      >
        {caption ? <caption id={captionId} className="sr-only">{caption}</caption> : null}
        <thead className="dt-header">
          <tr>
            {hasSelection ? (
              <th scope="col" className="dt-select-cell">
                {config.selectionMode === "multi" ? (
                  <input
                    type="checkbox"
                    aria-label="Select all rows on page"
                    checked={table.rows.length > 0 && table.rows.every((row) => table.selection.has(config.getRowId(row)))}
                    onChange={() => table.toggleAllOnPage()}
                  />
                ) : null}
              </th>
            ) : null}
            {table.columns.map((col) => {
              const ariaSort = table.sort?.columnId === col.id
                ? table.sort.direction === "asc"
                  ? "ascending"
                  : "descending"
                : col.sortable
                  ? "none"
                  : undefined;
              return (
                <th
                  key={col.id}
                  scope="col"
                  aria-sort={ariaSort}
                  className={[
                    "dt-header-cell",
                    col.stickyLeading ? "is-sticky-leading" : "",
                    `align-${col.align ?? "start"}`,
                  ].filter(Boolean).join(" ")}
                  style={col.width ? { width: col.width } : undefined}
                >
                  {col.sortable ? (
                    <button
                      type="button"
                      className="dt-sort-trigger"
                      onClick={() => table.cycleSort(col.id)}
                      aria-label={typeof col.headerLabel === "string" ? col.headerLabel : undefined}
                    >
                      {col.header}
                      <SortIndicator state={table.sort?.columnId === col.id ? table.sort.direction : null} />
                    </button>
                  ) : (
                    col.header
                  )}
                  {col.filterable ? (
                    <input
                      type="text"
                      className="dt-filter-input"
                      value={table.filter[col.id] ?? ""}
                      placeholder="Filter…"
                      aria-label={`Filter ${typeof col.headerLabel === "string" ? col.headerLabel : col.id}`}
                      onChange={(event) => table.setColumnFilter(col.id, event.currentTarget.value)}
                    />
                  ) : null}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {visibleRows.length === 0 ? (
            <tr>
              <td colSpan={colSpan}>
                <div className="dt-empty">
                  <EmptyState title={emptyTitle} body={emptyBody} action={emptyAction} />
                </div>
              </td>
            </tr>
          ) : (
            visibleRows.map((row, i) => {
              const id = config.getRowId(row);
              const selected = table.selection.has(id);
              return (
                <tr
                  key={id}
                  className="dt-row"
                  aria-selected={hasSelection ? selected : undefined}
                  aria-rowindex={(table.page - 1) * table.pageSize + i + 2}
                  data-selected={selected || undefined}
                  tabIndex={onRowActivate ? 0 : -1}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && onRowActivate) {
                      event.preventDefault();
                      onRowActivate(row);
                    } else if (event.key === " " && hasSelection) {
                      event.preventDefault();
                      table.toggleRow(id);
                    }
                  }}
                >
                  {hasSelection ? (
                    <td className="dt-select-cell">
                      <input
                        type="checkbox"
                        aria-label="Select row"
                        checked={selected}
                        onChange={() => table.toggleRow(id)}
                      />
                    </td>
                  ) : null}
                  {table.columns.map((col) => {
                    const ctx: CellCtx = {
                      rowIndex: i,
                      absoluteIndex: (table.page - 1) * table.pageSize + i,
                      density,
                      selected,
                    };
                    return (
                      <td
                        key={col.id}
                        className={`dt-cell align-${col.align ?? "start"}${col.stickyLeading ? " is-sticky-leading" : ""}`}
                        data-label={typeof col.headerLabel === "string" ? col.headerLabel : col.id}
                      >
                        {col.cell ? col.cell(row, ctx) : (col.accessor(row) as ReactNode) ?? ""}
                      </td>
                    );
                  })}
                </tr>
              );
            })
          )}
          {showSentinel ? (
            <tr ref={sentinelRef} className="dt-sentinel" aria-hidden="true">
              <td colSpan={colSpan} className="dt-sentinel-cell">
                Loading more rows… ({visibleRows.length} of {table.allFiltered.length})
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
      {showSentinel ? (
        <div className="dt-footer">
          <button
            type="button"
            className="dt-show-all"
            onClick={() => setWindowSize(table.allFiltered.length)}
          >
            Show all {table.allFiltered.length} rows
          </button>
        </div>
      ) : null}
      {config.pageSize !== 0 && table.pageCount > 1 ? (
        <div className="dt-footer">
          <Pagination page={table.page} pages={table.pageCount} />
        </div>
      ) : null}
    </div>
  );
}
