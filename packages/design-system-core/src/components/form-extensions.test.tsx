import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { FieldArray, FileField } from "./form-extensions";

describe("FieldArray", () => {
  it("renders defaultValue items with stable keys derived from index", () => {
    render(
      <FieldArray<{ email: string }>
        name="recipients"
        defaultValue={[{ email: "a@x" }, { email: "b@x" }]}
      >
        {(handle) => (
          <ul>
            {handle.items.map((item, i) => (
              <li key={item.key} data-key={item.key} data-name={handle.fieldName(i, "email")}>
                {item.value.email}
              </li>
            ))}
          </ul>
        )}
      </FieldArray>,
    );
    const items = screen.getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveAttribute("data-key", "recipients-0");
    expect(items[0]).toHaveAttribute("data-name", "recipients.0.email");
    expect(items[1]).toHaveAttribute("data-name", "recipients.1.email");
  });

  it("add/remove/move/clear preserves stable keys (new items get a fresh seed)", () => {
    function Probe() {
      return (
        <FieldArray<{ email: string }> name="r" defaultValue={[{ email: "a" }, { email: "b" }]}>
          {(handle) => (
            <div>
              <ul>
                {handle.items.map((item) => (
                  <li key={item.key} data-key={item.key}>
                    {item.value.email}
                  </li>
                ))}
              </ul>
              <button onClick={() => handle.add({ email: "c" })}>add</button>
              <button onClick={() => handle.remove(0)}>remove0</button>
              <button onClick={() => handle.move(0, 1)}>move</button>
              <button onClick={() => handle.clear()}>clear</button>
            </div>
          )}
        </FieldArray>
      );
    }
    render(<Probe />);
    fireEvent.click(screen.getByText("add"));
    let keys = screen.getAllByRole("listitem").map((el) => el.getAttribute("data-key"));
    expect(keys).toEqual(["r-0", "r-1", "r-2"]);
    fireEvent.click(screen.getByText("remove0"));
    keys = screen.getAllByRole("listitem").map((el) => el.getAttribute("data-key"));
    expect(keys).toEqual(["r-1", "r-2"]);
    fireEvent.click(screen.getByText("move"));
    keys = screen.getAllByRole("listitem").map((el) => el.getAttribute("data-key"));
    expect(keys).toEqual(["r-2", "r-1"]);
    fireEvent.click(screen.getByText("clear"));
    expect(screen.queryAllByRole("listitem")).toHaveLength(0);
  });

  it("fieldName returns the dotted submit-name shape", () => {
    let captured: string[] = [];
    render(
      <FieldArray<{ email: string }> name="recipients" defaultValue={[{ email: "a" }]}>
        {(handle) => {
          captured = [handle.fieldName(0), handle.fieldName(0, "email")];
          return <span />;
        }}
      </FieldArray>,
    );
    expect(captured).toEqual(["recipients.0", "recipients.0.email"]);
  });
});

function makeFile(name: string, type: string, size = 100) {
  const blob = new Blob([new Uint8Array(size)], { type });
  return new File([blob], name, { type });
}

describe("FileField", () => {
  it("filters dropped files by accept and reports rejected types via onError", () => {
    const onValueChange = vi.fn();
    const onError = vi.fn();
    render(
      <FileField
        accept="image/*,.pdf"
        multiple
        onValueChange={onValueChange}
        onError={onError}
      />,
    );
    const dropzone = screen.getByText(/Choose files or drop here/);
    const png = makeFile("a.png", "image/png");
    const txt = makeFile("b.txt", "text/plain");
    const pdf = makeFile("c.pdf", "application/pdf");
    fireEvent.drop(dropzone, { dataTransfer: { files: [png, txt, pdf] } });
    expect(onValueChange).toHaveBeenCalledWith([png, pdf]);
    expect(onError).toHaveBeenCalledWith({ code: "type", file: txt });
  });

  it("rejects files larger than maxSize via onError", () => {
    const onValueChange = vi.fn();
    const onError = vi.fn();
    render(
      <FileField multiple maxSize={50} onValueChange={onValueChange} onError={onError} />,
    );
    const dropzone = screen.getByText(/Choose files or drop here/);
    const big = makeFile("big.bin", "application/octet-stream", 200);
    const small = makeFile("small.bin", "application/octet-stream", 10);
    fireEvent.drop(dropzone, { dataTransfer: { files: [big, small] } });
    expect(onValueChange).toHaveBeenCalledWith([small]);
    expect(onError).toHaveBeenCalledWith({ code: "size", file: big });
  });

  it("clamps to one file when multiple is false", () => {
    const onValueChange = vi.fn();
    render(<FileField onValueChange={onValueChange} />);
    const dropzone = screen.getByText(/Choose files or drop here/);
    const a = makeFile("a.txt", "text/plain");
    const b = makeFile("b.txt", "text/plain");
    fireEvent.drop(dropzone, { dataTransfer: { files: [a, b] } });
    expect(onValueChange).toHaveBeenCalledWith([a]);
  });

  it("renders the selected-file count and per-file list when files are committed", () => {
    const { rerender } = render(<FileField multiple />);
    expect(screen.getByText("Choose files or drop here")).toBeInTheDocument();
    const a = makeFile("a.txt", "text/plain", 100);
    const b = makeFile("b.txt", "text/plain", 100);
    rerender(<FileField multiple value={[a, b]} />);
    expect(screen.getByText("2 files selected")).toBeInTheDocument();
    expect(screen.getByText("a.txt")).toBeInTheDocument();
    expect(screen.getByText("b.txt")).toBeInTheDocument();
  });

  it("ignores drops while disabled", () => {
    const onValueChange = vi.fn();
    render(<FileField disabled onValueChange={onValueChange} />);
    const dropzone = screen.getByText(/Choose files or drop here/);
    fireEvent.drop(dropzone, {
      dataTransfer: { files: [makeFile("x.txt", "text/plain")] },
    });
    expect(onValueChange).not.toHaveBeenCalled();
  });

  it("toggles the data-dragging attribute on dragOver / dragLeave", () => {
    render(<FileField />);
    const wrapper = document.querySelector(".file-field") as HTMLElement;
    const dropzone = wrapper.querySelector("label") as HTMLElement;
    expect(wrapper.hasAttribute("data-dragging")).toBe(false);
    fireEvent.dragOver(dropzone);
    expect(wrapper.getAttribute("data-dragging")).toBe("true");
    fireEvent.dragLeave(dropzone);
    expect(wrapper.hasAttribute("data-dragging")).toBe(false);
  });
});
