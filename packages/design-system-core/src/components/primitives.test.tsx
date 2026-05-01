import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import {
  Accordion,
  Breadcrumbs,
  Combobox,
  Disclosure,
  IconButton,
  MenuButton,
  Popover,
  RadioGroup,
  SliderField,
  Toolbar,
} from "./primitives";

describe("library primitives", () => {
  it("requires a stable accessible name for icon-only actions", () => {
    render(<IconButton label="Refresh evidence" icon={<span aria-hidden="true">R</span>} />);
    expect(screen.getByRole("button", { name: "Refresh evidence" })).toBeInTheDocument();
  });

  it("groups toolbar controls under a named toolbar", () => {
    render(
      <Toolbar label="Receipt actions">
        <IconButton label="Copy receipt" icon={<span aria-hidden="true">C</span>} />
      </Toolbar>,
    );
    expect(screen.getByRole("toolbar", { name: "Receipt actions" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy receipt" })).toBeInTheDocument();
  });

  it("toggles disclosure content with aria wiring", () => {
    render(<Disclosure title="Source details">Signed receipt hash</Disclosure>);
    const trigger = screen.getByRole("button", { name: "Source details" });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("Signed receipt hash")).toBeVisible();
  });

  it("supports single-open accordion behavior", () => {
    render(
      <Accordion
        items={[
          { id: "intent", title: "Intent", children: "Intent body" },
          { id: "policy", title: "Policy", children: "Policy body" },
        ]}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Intent" }));
    expect(screen.getByText("Intent body")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Policy" }));
    expect(screen.getByText("Policy body")).toBeVisible();
    expect(screen.getByText("Intent body")).not.toBeVisible();
  });

  it("renders breadcrumbs with aria-current on the final item", () => {
    render(
      <Breadcrumbs
        items={[
          { label: "Actions", href: "/actions" },
          { label: "Receipt ep_9f82c31a" },
        ]}
      />,
    );
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toBeInTheDocument();
    expect(screen.getByText("Receipt ep_9f82c31a")).toHaveAttribute("aria-current", "page");
  });

  it("opens popover content and closes with Escape", () => {
    render(
      <Popover label="Open filters" title="Filters">
        <p>Production only</p>
      </Popover>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Open filters" }));
    const dialog = screen.getByRole("dialog", { name: "Filters" });
    expect(dialog).toBeVisible();
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(dialog).not.toBeVisible();
  });

  it("uses menu roles and routes selected actions", () => {
    const onSelect = vi.fn();
    render(<MenuButton label="More" items={[{ id: "copy", label: "Copy receipt", onSelect }]} />);
    fireEvent.click(screen.getByRole("button", { name: /More/ }));
    const menu = screen.getByRole("menu");
    fireEvent.click(within(menu).getByRole("menuitem", { name: "Copy receipt" }));
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(menu).not.toBeVisible();
  });

  it("keeps radio groups and sliders native", () => {
    const onRadioChange = vi.fn();
    const onSliderChange = vi.fn();
    render(
      <>
        <RadioGroup
          legend="Mode"
          options={[
            { value: "live", label: "Live" },
            { value: "retained", label: "Retained" },
          ]}
          defaultValue="live"
          onValueChange={onRadioChange}
        />
        <SliderField label="Density" min={0} max={10} defaultValue={4} onValueChange={onSliderChange} />
      </>,
    );
    fireEvent.click(screen.getByRole("radio", { name: "Retained" }));
    expect(onRadioChange).toHaveBeenCalledWith("retained");
    fireEvent.change(screen.getByRole("slider", { name: "Density" }), { target: { value: "7" } });
    expect(onSliderChange).toHaveBeenCalledWith(7);
  });

  it("Combobox: ARIA wiring + keyboard nav + Enter selects", () => {
    const onValueChange = vi.fn();
    const options = [
      { value: "stripe.allow_v3", label: "stripe.allow_v3" },
      { value: "stripe.deny_v2", label: "stripe.deny_v2" },
      { value: "github.escalate_v1", label: "github.escalate_v1", hint: "owner: security" },
    ] as const;
    render(<Combobox label="Policy" options={options} onValueChange={onValueChange} />);
    const input = screen.getByRole("combobox", { name: "Policy" });
    expect(input).toHaveAttribute("aria-expanded", "false");
    fireEvent.focus(input);
    expect(input).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("listbox", { name: "Policy" })).toBeInTheDocument();
    fireEvent.keyDown(input, { key: "ArrowDown" });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onValueChange).toHaveBeenCalledWith("stripe.deny_v2");
    expect(input).toHaveAttribute("aria-expanded", "false");
    expect((input as HTMLInputElement).value).toBe("stripe.deny_v2");
  });

  it("Combobox: filters options as the user types and shows empty state", () => {
    const options = [
      { value: "alpha", label: "alpha" },
      { value: "beta", label: "beta" },
      { value: "gamma", label: "gamma" },
    ] as const;
    render(<Combobox label="Channel" options={options} />);
    const input = screen.getByRole("combobox", { name: "Channel" });
    fireEvent.focus(input);
    fireEvent.change(input, { target: { value: "be" } });
    const listbox = screen.getByRole("listbox", { name: "Channel" });
    const visible = within(listbox).getAllByRole("option");
    expect(visible).toHaveLength(1);
    expect(visible[0]).toHaveTextContent("beta");
    fireEvent.change(input, { target: { value: "zzz" } });
    expect(within(listbox).queryAllByRole("option")).toHaveLength(0);
    expect(within(listbox).getByRole("status")).toHaveTextContent(/no matches/i);
  });

  it("Combobox: Escape closes without selecting and restores last value", () => {
    const options = [
      { value: "alpha", label: "alpha" },
      { value: "beta", label: "beta" },
    ] as const;
    render(<Combobox label="Channel" options={options} defaultValue="alpha" />);
    const input = screen.getByRole("combobox", { name: "Channel" }) as HTMLInputElement;
    expect(input.value).toBe("alpha");
    fireEvent.focus(input);
    fireEvent.change(input, { target: { value: "bet" } });
    expect(input.value).toBe("bet");
    fireEvent.keyDown(input, { key: "Escape" });
    expect(input).toHaveAttribute("aria-expanded", "false");
    expect(input.value).toBe("alpha");
  });

  it("Combobox: skips disabled options on keyboard navigation", () => {
    const onValueChange = vi.fn();
    const options = [
      { value: "alpha", label: "alpha" },
      { value: "beta", label: "beta", disabled: true },
      { value: "gamma", label: "gamma" },
    ] as const;
    render(<Combobox label="Channel" options={options} onValueChange={onValueChange} />);
    const input = screen.getByRole("combobox", { name: "Channel" });
    fireEvent.focus(input);
    // First press: from initial activeIndex 0 (alpha) → next enabled = gamma (skip beta)
    fireEvent.keyDown(input, { key: "ArrowDown" });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onValueChange).toHaveBeenCalledWith("gamma");
  });
});
