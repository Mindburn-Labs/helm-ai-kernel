import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DataTable, type DataTableColumn } from "./data-table";

interface Row {
  readonly id: string;
  readonly name: string;
  readonly amount: number;
}

const rows: Row[] = [
  { id: "a", name: "alpha", amount: 30 },
  { id: "b", name: "bravo", amount: 10 },
  { id: "c", name: "charlie", amount: 20 },
];

const columns: DataTableColumn<Row>[] = [
  { id: "name", header: "Name", accessor: (r) => r.name, sortable: true, filterable: true, headerLabel: "Name" },
  { id: "amount", header: "Amount", accessor: (r) => r.amount, sortable: true, align: "end", headerLabel: "Amount" },
];

describe("DataTable", () => {
  it("clicking a sortable header cycles asc → desc → none and updates aria-sort", () => {
    render(<DataTable rows={rows} columns={columns} getRowId={(r) => r.id} />);
    const header = screen.getByRole("columnheader", { name: /Name/i });
    expect(header).toHaveAttribute("aria-sort", "none");

    const trigger = within(header).getByRole("button");
    fireEvent.click(trigger);
    expect(header).toHaveAttribute("aria-sort", "ascending");

    let bodyRows = screen.getAllByRole("row").slice(1);
    expect(bodyRows[0]).toHaveTextContent("alpha");
    expect(bodyRows[2]).toHaveTextContent("charlie");

    fireEvent.click(trigger);
    expect(header).toHaveAttribute("aria-sort", "descending");
    bodyRows = screen.getAllByRole("row").slice(1);
    expect(bodyRows[0]).toHaveTextContent("charlie");
    expect(bodyRows[2]).toHaveTextContent("alpha");

    fireEvent.click(trigger);
    expect(header).toHaveAttribute("aria-sort", "none");
  });

  it("filter narrows rows to matches; empty state appears when nothing matches", () => {
    render(<DataTable rows={rows} columns={columns} getRowId={(r) => r.id} />);
    const filter = screen.getByRole("textbox", { name: /Filter Name/i });
    fireEvent.change(filter, { target: { value: "bra" } });
    expect(screen.queryByText("alpha")).not.toBeInTheDocument();
    expect(screen.getByText("bravo")).toBeInTheDocument();

    fireEvent.change(filter, { target: { value: "zzz" } });
    expect(screen.getByText(/no matching rows/i)).toBeInTheDocument();
  });

  it("multi selection persists across rows and aria-selected reflects state", () => {
    render(
      <DataTable rows={rows} columns={columns} getRowId={(r) => r.id} selectionMode="multi" />,
    );
    const firstRowCheckbox = screen.getAllByRole("checkbox", { name: "Select row" })[0];
    expect(firstRowCheckbox).not.toBeUndefined();
    fireEvent.click(firstRowCheckbox!);
    expect(firstRowCheckbox).toBeChecked();
    const firstRow = firstRowCheckbox!.closest("tr") as HTMLElement;
    expect(firstRow).toHaveAttribute("aria-selected", "true");
  });

  it("non-sortable columns render no sort UI and have no aria-sort", () => {
    const noSort: DataTableColumn<Row>[] = [
      { id: "name", header: "Name", accessor: (r) => r.name },
    ];
    render(<DataTable rows={rows} columns={noSort} getRowId={(r) => r.id} />);
    const header = screen.getByRole("columnheader", { name: /Name/i });
    expect(header).not.toHaveAttribute("aria-sort");
    expect(within(header).queryByRole("button")).toBeNull();
  });

  it("ARIA wiring: role=table + aria-rowcount + aria-multiselectable", () => {
    render(
      <DataTable rows={rows} columns={columns} getRowId={(r) => r.id} selectionMode="multi" />,
    );
    const table = screen.getByRole("table");
    expect(table).toHaveAttribute("aria-rowcount", String(rows.length + 1));
    expect(table).toHaveAttribute("aria-multiselectable", "true");
  });

  it("Enter on a row activates the row when onRowActivate is provided", () => {
    const onRowActivate = vi.fn<(r: Row) => void>();
    render(<DataTable rows={rows} columns={columns} getRowId={(r) => r.id} onRowActivate={onRowActivate} />);
    const allRows = screen.getAllByRole("row").slice(1);
    fireEvent.keyDown(allRows[0]!, { key: "Enter" });
    expect(onRowActivate).toHaveBeenCalledTimes(1);
  });

  it("virtualize=true + pageSize=0 windows the DOM and reports the full count via aria-rowcount", () => {
    type BigRow = { readonly id: string; readonly name: string };
    const big: BigRow[] = Array.from({ length: 500 }, (_, i) => ({
      id: `r${i}`,
      name: `Row ${i}`,
    }));
    const cols = [
      { id: "name", header: "Name", accessor: (r: BigRow) => r.name },
    ] as const;
    render(
      <DataTable
        rows={big}
        columns={cols as unknown as Parameters<typeof DataTable<BigRow>>[0]["columns"]}
        getRowId={(r) => r.id}
        pageSize={0}
        virtualize
      />,
    );
    const table = screen.getByRole("table");
    expect(table.getAttribute("aria-rowcount")).toBe("501");
    const dataRows = screen.getAllByRole("row").slice(1);
    expect(dataRows.length).toBeLessThan(big.length);
    expect(dataRows.length).toBeGreaterThanOrEqual(100);
    expect(screen.getByRole("button", { name: /Show all 500 rows/ })).toBeInTheDocument();
  });

  it("Show-all button expands the window to the full filtered count", () => {
    type BigRow = { readonly id: string; readonly name: string };
    const big: BigRow[] = Array.from({ length: 250 }, (_, i) => ({
      id: `r${i}`,
      name: `Row ${i}`,
    }));
    const cols = [
      { id: "name", header: "Name", accessor: (r: BigRow) => r.name },
    ] as const;
    render(
      <DataTable
        rows={big}
        columns={cols as unknown as Parameters<typeof DataTable<BigRow>>[0]["columns"]}
        getRowId={(r) => r.id}
        pageSize={0}
        virtualize
      />,
    );
    const showAll = screen.getByRole("button", { name: /Show all 250 rows/ });
    fireEvent.click(showAll);
    const dataRows = screen.getAllByRole("row").slice(1);
    expect(dataRows.length).toBe(250);
  });

  it("virtualize without pageSize=0 falls back to standard pagination (no windowing)", () => {
    type BigRow = { readonly id: string; readonly name: string };
    const big: BigRow[] = Array.from({ length: 200 }, (_, i) => ({
      id: `r${i}`,
      name: `Row ${i}`,
    }));
    const cols = [
      { id: "name", header: "Name", accessor: (r: BigRow) => r.name },
    ] as const;
    render(
      <DataTable
        rows={big}
        columns={cols as unknown as Parameters<typeof DataTable<BigRow>>[0]["columns"]}
        getRowId={(r) => r.id}
        pageSize={25}
        virtualize
      />,
    );
    const dataRows = screen.getAllByRole("row").slice(1);
    expect(dataRows.length).toBe(25);
    expect(screen.queryByRole("button", { name: /Show all/ })).toBeNull();
  });
});
