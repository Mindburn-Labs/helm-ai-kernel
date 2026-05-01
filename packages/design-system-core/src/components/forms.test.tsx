import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import {
  Form,
  FormField,
  FormSummary,
  NumberInput,
  SelectField,
  TextInput,
  useFormState,
  type FormErrors,
} from "./forms";

describe("FormField a11y wiring", () => {
  it("connects label to TextInput via htmlFor/id and reflects hint via aria-describedby", () => {
    render(
      <FormField label="Confirmation phrase" hint="Type to enable approval">
        <TextInput placeholder="phrase" />
      </FormField>,
    );
    const input = screen.getByLabelText("Confirmation phrase") as HTMLInputElement;
    expect(input.tagName).toBe("INPUT");
    const describedBy = input.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    expect(screen.getByText("Type to enable approval")).toHaveAttribute("id", describedBy ?? "");
  });

  it("sets aria-invalid and surfaces an alert when error is set", () => {
    render(
      <FormField label="Phrase" error="Phrase must match production deploy.">
        <TextInput placeholder="phrase" />
      </FormField>,
    );
    const input = screen.getByLabelText("Phrase") as HTMLInputElement;
    expect(input).toHaveAttribute("aria-invalid", "true");
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Phrase must match production deploy.");
    const describedBy = input.getAttribute("aria-describedby") ?? "";
    expect(describedBy.split(" ")).toContain(alert.getAttribute("id") ?? "");
  });

  it("propagates required + aria-required when FormField requires the field", () => {
    render(
      <FormField label="Owner" required>
        <SelectField value="alpha" options={["alpha", "beta"] as const} />
      </FormField>,
    );
    const select = screen.getByLabelText(/Owner/) as HTMLSelectElement;
    expect(select).toBeRequired();
    expect(select).toHaveAttribute("aria-required", "true");
  });

  it("merges hint and error ids in aria-describedby when both are set", () => {
    render(
      <FormField label="Phrase" hint="Type to enable" error="Mismatch">
        <TextInput />
      </FormField>,
    );
    const input = screen.getByLabelText("Phrase") as HTMLInputElement;
    const describedBy = input.getAttribute("aria-describedby") ?? "";
    const tokens = describedBy.split(" ");
    expect(tokens).toHaveLength(2);
    const hintId = screen.getByText("Type to enable").getAttribute("id");
    const errorId = screen.getByRole("alert").getAttribute("id");
    expect(tokens).toContain(hintId ?? "");
    expect(tokens).toContain(errorId ?? "");
  });
});

describe("Form orchestration", () => {
  it("calls onSubmit with parsed FormData values when validation passes", () => {
    const onSubmit = vi.fn();
    render(
      <Form aria-label="Policy form" onSubmit={onSubmit}>
        <FormField label="Owner">
          <TextInput name="owner" defaultValue="finance-governance" />
        </FormField>
        <FormField label="Environment">
          <SelectField name="env" value="production" options={["production", "staging", "dev"] as const} />
        </FormField>
        <button type="submit">Submit</button>
      </Form>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    const [values] = onSubmit.mock.calls[0] as [Record<string, string>];
    expect(values.owner).toBe("finance-governance");
    expect(values.env).toBe("production");
  });

  it("blocks onSubmit when validate returns errors and routes them via onValidationError", () => {
    const onSubmit = vi.fn();
    const onValidationError = vi.fn();
    const validate = (values: Record<string, FormDataEntryValue | FormDataEntryValue[]>): FormErrors => {
      if (!values.owner) return { owner: "owner is required" };
      return {};
    };
    render(
      <Form aria-label="Policy form" onSubmit={onSubmit} validate={validate} onValidationError={onValidationError}>
        <FormField label="Owner">
          <TextInput name="owner" />
        </FormField>
        <FormSummary />
        <button type="submit">Submit</button>
      </Form>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    expect(onSubmit).not.toHaveBeenCalled();
    expect(onValidationError).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("alert")).toHaveTextContent(/owner is required/i);
  });

  it("FormSummary renders nothing while errors are empty", () => {
    render(
      <Form aria-label="ok" onSubmit={() => {}}>
        <FormSummary />
        <button type="submit">Submit</button>
      </Form>,
    );
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("useFormState returns null outside a Form (graceful degradation)", () => {
    function Probe() {
      const ctx = useFormState();
      return <span data-testid="ctx-presence">{ctx === null ? "null" : "context"}</span>;
    }
    render(<Probe />);
    expect(screen.getByTestId("ctx-presence")).toHaveTextContent("null");
  });
});

describe("NumberInput", () => {
  it("emits onValueChange with the parsed number on input and null when emptied", () => {
    const onValueChange = vi.fn();
    render(<FormField label="Amount"><NumberInput onValueChange={onValueChange} /></FormField>);
    const input = screen.getByLabelText("Amount") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "42" } });
    expect(onValueChange).toHaveBeenLastCalledWith(42);
    fireEvent.change(input, { target: { value: "" } });
    expect(onValueChange).toHaveBeenLastCalledWith(null);
  });

  it("clamps to [min, max] on blur", () => {
    const onValueChange = vi.fn();
    render(
      <FormField label="Amount">
        <NumberInput min={0} max={10} onValueChange={onValueChange} />
      </FormField>,
    );
    const input = screen.getByLabelText("Amount") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "999" } });
    fireEvent.blur(input);
    expect(input.value).toBe("10");
    expect(onValueChange).toHaveBeenLastCalledWith(10);
  });

  it("ArrowUp adds step and Shift+ArrowUp adds step×10", () => {
    const onValueChange = vi.fn();
    render(
      <FormField label="Amount">
        <NumberInput defaultValue={0} step={2} onValueChange={onValueChange} />
      </FormField>,
    );
    const input = screen.getByLabelText("Amount") as HTMLInputElement;
    fireEvent.keyDown(input, { key: "ArrowUp" });
    expect(onValueChange).toHaveBeenLastCalledWith(2);
    fireEvent.keyDown(input, { key: "ArrowUp", shiftKey: true });
    expect(onValueChange).toHaveBeenLastCalledWith(22);
  });

  it("rejects keystrokes that produce an invalid numeric draft (no negatives when min >= 0)", () => {
    render(
      <FormField label="Amount">
        <NumberInput min={0} />
      </FormField>,
    );
    const input = screen.getByLabelText("Amount") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "-5" } });
    expect(input.value).not.toBe("-5");
    fireEvent.change(input, { target: { value: "abc" } });
    expect(input.value).not.toBe("abc");
  });

  it("respects FormField context wiring (id, aria-invalid, aria-required)", () => {
    render(
      <FormField label="Amount" error="Required" required>
        <NumberInput />
      </FormField>,
    );
    const input = screen.getByLabelText(/Amount/) as HTMLInputElement;
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAttribute("aria-required", "true");
  });

  it("FormField auto-binds its error from Form context when given matching `name`", () => {
    render(
      <Form
        aria-label="Auto-bind"
        onSubmit={() => {}}
        validate={(values): FormErrors => (values.amount ? {} : { amount: "amount is required" })}
      >
        <FormField label="Amount" name="amount">
          <NumberInput name="amount" />
        </FormField>
        <button type="submit">Submit</button>
      </Form>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(/amount is required/i);
    const input = screen.getByLabelText(/Amount/) as HTMLInputElement;
    expect(input).toHaveAttribute("aria-invalid", "true");
  });

  it("submits via Form FormData using its name attribute", () => {
    const onSubmit = vi.fn();
    render(
      <Form aria-label="Amount form" onSubmit={onSubmit}>
        <FormField label="Amount">
          <NumberInput name="amount" defaultValue={5} />
        </FormField>
        <button type="submit">Submit</button>
      </Form>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    const [values] = onSubmit.mock.calls[0] as [Record<string, string>];
    expect(values.amount).toBe("5");
  });
});
