import type { LaunchpadSubstrate } from "./types";

export function SubstratePicker({
  substrates,
  selected,
  disabled,
  onSelect,
}: {
  substrates: LaunchpadSubstrate[];
  selected: string;
  disabled?: boolean;
  onSelect: (substrateId: string) => void;
}) {
  return (
    <label className="launchpad-field">
      <span>Substrate</span>
      <select value={selected} disabled={disabled || substrates.length === 0} onChange={(event) => onSelect(event.target.value)}>
        {substrates.length === 0 ? <option value="">No substrates returned</option> : null}
        {substrates.map((substrate) => (
          <option key={substrate.id} value={substrate.id}>
            {substrate.name} · {substrate.availability}
          </option>
        ))}
      </select>
    </label>
  );
}
