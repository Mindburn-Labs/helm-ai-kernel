import type { LaunchpadApp } from "./types";

export function AppPicker({
  apps,
  selected,
  onSelect,
}: {
  apps: LaunchpadApp[];
  selected: string;
  onSelect: (appId: string) => void;
}) {
  return (
    <label className="launchpad-field">
      <span>App</span>
      <select value={selected} onChange={(event) => onSelect(event.target.value)}>
        {apps.map((app) => (
          <option key={app.id} value={app.id}>
            {app.name} · {app.availability}
          </option>
        ))}
      </select>
    </label>
  );
}
