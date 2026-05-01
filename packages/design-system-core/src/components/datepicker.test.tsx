import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Calendar, DatePicker } from "./datepicker";
import { Form, FormField } from "./forms";

describe("Calendar", () => {
  it("emits onValueChange with the clicked day", () => {
    const onValueChange = vi.fn<(d: Date) => void>();
    render(<Calendar focusedDate={new Date(2026, 3, 15)} onValueChange={onValueChange} locale="en-GB" />);
    const day = document.querySelector('[data-iso="2026-04-20"]') as HTMLElement;
    fireEvent.click(day);
    expect(onValueChange).toHaveBeenCalledTimes(1);
    const arg = onValueChange.mock.calls[0]?.[0] as Date;
    expect(arg.getFullYear()).toBe(2026);
    expect(arg.getMonth()).toBe(3);
    expect(arg.getDate()).toBe(20);
  });

  it("ArrowRight moves focus by one day; PageDown by one month", () => {
    const onFocusedDateChange = vi.fn<(d: Date) => void>();
    render(
      <Calendar
        focusedDate={new Date(2026, 3, 15)}
        onFocusedDateChange={onFocusedDateChange}
        locale="en-GB"
      />,
    );
    const grid = screen.getByRole("grid");
    fireEvent.keyDown(grid, { key: "ArrowRight" });
    const afterArrow = onFocusedDateChange.mock.calls[0]?.[0] as Date;
    expect(afterArrow.getDate()).toBe(16);
    fireEvent.keyDown(grid, { key: "PageDown" });
    const afterPageDown = onFocusedDateChange.mock.calls[1]?.[0] as Date;
    expect(afterPageDown.getMonth()).toBe(4); // May
  });

  it("clamps to [min, max]: dates outside the range are aria-disabled and ignored on click", () => {
    const onValueChange = vi.fn<(d: Date) => void>();
    render(
      <Calendar
        focusedDate={new Date(2026, 3, 15)}
        min={new Date(2026, 3, 10)}
        max={new Date(2026, 3, 20)}
        onValueChange={onValueChange}
        locale="en-GB"
      />,
    );
    const day9 = document.querySelector('[data-iso="2026-04-09"]') as HTMLElement;
    expect(day9).toHaveAttribute("aria-disabled", "true");
    fireEvent.click(day9);
    expect(onValueChange).not.toHaveBeenCalled();
    const day15 = document.querySelector('[data-iso="2026-04-15"]') as HTMLElement;
    fireEvent.click(day15);
    expect(onValueChange).toHaveBeenCalledTimes(1);
  });
});

describe("DatePicker", () => {
  it("opens on trigger click and exposes ARIA combobox + dialog wiring", () => {
    render(<DatePicker label="Due date" defaultValue={new Date(2026, 3, 15)} locale="en-GB" />);
    const trigger = screen.getByRole("combobox", { name: /Due date/i });
    expect(trigger).toHaveAttribute("aria-haspopup", "dialog");
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("dialog", { name: "Due date" })).toBeInTheDocument();
  });

  it("Escape closes the popover and returns focus to the trigger", () => {
    render(<DatePicker label="Due date" defaultValue={new Date(2026, 3, 15)} locale="en-GB" />);
    const trigger = screen.getByRole("combobox", { name: /Due date/i });
    fireEvent.click(trigger);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(document.activeElement).toBe(trigger);
  });

  it("submits the selected date as ISO YYYY-MM-DD via Form FormData", () => {
    const onSubmit = vi.fn();
    render(
      <Form aria-label="Due-date form" onSubmit={onSubmit}>
        <FormField label="Due date">
          <DatePicker label="Due date" defaultValue={new Date(2026, 3, 15)} name="due" locale="en-GB" />
        </FormField>
        <button type="submit">Submit</button>
      </Form>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    const [values] = onSubmit.mock.calls[0] as [Record<string, string>];
    expect(values.due).toBe("2026-04-15");
  });

  it("FormField context surfaces aria-required + aria-invalid on the trigger", () => {
    render(
      <FormField label="Due date" required error="Required">
        <DatePicker label="Due date" />
      </FormField>,
    );
    const trigger = screen.getByRole("combobox", { name: /Due date/i });
    expect(trigger).toHaveAttribute("aria-required", "true");
    expect(trigger).toHaveAttribute("aria-invalid", "true");
  });

  it("clicking a day in the calendar selects it and closes the popover", () => {
    const onValueChange = vi.fn<(d: Date | null) => void>();
    render(
      <DatePicker
        label="Due date"
        defaultValue={new Date(2026, 3, 15)}
        onValueChange={onValueChange}
        locale="en-GB"
      />,
    );
    const trigger = screen.getByRole("combobox", { name: /Due date/i });
    fireEvent.click(trigger);
    const dialog = screen.getByRole("dialog", { name: "Due date" });
    const day = within(dialog).getByRole("gridcell", {
      name: (_name, element) => element.getAttribute("data-iso") === "2026-04-20",
    });
    fireEvent.click(day);
    expect(onValueChange).toHaveBeenCalledTimes(1);
    expect(trigger).toHaveAttribute("aria-expanded", "false");
  });
});
