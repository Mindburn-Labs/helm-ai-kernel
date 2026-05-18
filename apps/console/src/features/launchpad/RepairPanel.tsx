export function RepairPanel({ disabled, onRepair }: { disabled: boolean; onRepair: () => void }) {
  return (
    <button className="launchpad-action" type="button" disabled={disabled} onClick={onRepair}>
      Repair
    </button>
  );
}
