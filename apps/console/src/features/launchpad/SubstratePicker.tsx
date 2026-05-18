import type { LaunchpadSubstrate } from "./types";

export function SubstratePicker({
  substrates,
  selected,
  onSelect,
}: {
  substrates: LaunchpadSubstrate[];
  selected: string;
  onSelect: (substrateId: string) => void;
}) {
  return (
    <label className="launchpad-field">
      <span>Substrate</span>
      <select value={selected} onChange={(event) => onSelect(event.target.value)}>
        {substrates.map((substrate) => (
          <option key={substrate.id} value={substrate.id}>
            {substrate.name} · {substrate.availability}
          </option>
        ))}
      </select>
    </label>
  );
}
