import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ProcessStepRow, StatusLine, StatusPill } from "./status";

describe("status primitives", () => {
  it("keeps long process labels outside the status pill", () => {
    render(<ProcessStepRow state="retrieving_context" title="Retrieving context" detail="Collecting scoped evidence sources for the selected receipt." />);

    expect(screen.getByText("RETRIEVING CONTEXT").closest(".status-pill")).not.toBeNull();
    expect(screen.getByText("Retrieving context").parentElement).toHaveClass("process-step-copy");
  });

  it("renders status lines with readable copy and semantic pill", () => {
    render(<StatusLine state="verified" label="Signature verified" detail="Manifest hash matched." />);

    expect(screen.getByText("VERIFIED").closest(".status-pill")).not.toBeNull();
    expect(screen.getByText("Signature verified")).toBeInTheDocument();
  });

  it("supports compact icon-only filter dot pills", () => {
    render(<StatusPill state="deny" label="" ariaLabel="deny filter state" />);
    expect(screen.getByLabelText("deny filter state")).toHaveClass("status-pill");
  });
});
