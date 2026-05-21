import { useEffect, useState } from "react";

export function TeardownPanel({ disabled, onDelete }: { disabled: boolean; onDelete: () => void }) {
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    if (!armed) return undefined;
    const timer = window.setTimeout(() => setArmed(false), 7000);
    return () => window.clearTimeout(timer);
  }, [armed]);

  const handleClick = () => {
    if (!armed) {
      setArmed(true);
      return;
    }
    setArmed(false);
    onDelete();
  };

  return (
    <div className="teardown-control" role="group" aria-label="Teardown launch">
      <button className="launchpad-action launchpad-action-danger" type="button" disabled={disabled} aria-pressed={armed} onClick={handleClick}>
        {armed ? "Confirm delete" : "Delete"}
      </button>
      {armed ? (
        <button className="launchpad-action" type="button" onClick={() => setArmed(false)}>
          Cancel
        </button>
      ) : null}
    </div>
  );
}
