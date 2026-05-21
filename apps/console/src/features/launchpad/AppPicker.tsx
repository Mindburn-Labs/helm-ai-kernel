import type { LaunchpadApp } from "./types";

export function AppPicker({
  apps,
  selected,
  disabled,
  onSelect,
}: {
  apps: LaunchpadApp[];
  selected: string;
  disabled?: boolean;
  onSelect: (appId: string) => void;
}) {
  return (
    <label className="launchpad-field">
      <span>App</span>
      <select value={selected} disabled={disabled || apps.length === 0} onChange={(event) => onSelect(event.target.value)}>
        {apps.length === 0 ? <option value="">No apps returned</option> : null}
        {apps.map((app) => (
          <option key={app.id} value={app.id}>
            {app.name} · {app.availability}
          </option>
        ))}
      </select>
    </label>
  );
}
