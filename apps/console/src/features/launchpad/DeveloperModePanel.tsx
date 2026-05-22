import type { ReactNode } from "react";

export function DeveloperModePanel({
  title,
  children,
  raw,
}: {
  readonly title: string;
  readonly children?: ReactNode;
  readonly raw?: unknown;
}) {
  return (
    <details className="developer-mode-panel">
      <summary>{title}</summary>
      {children}
      {raw !== undefined ? <pre className="launchpad-code">{JSON.stringify(raw, null, 2)}</pre> : null}
    </details>
  );
}
