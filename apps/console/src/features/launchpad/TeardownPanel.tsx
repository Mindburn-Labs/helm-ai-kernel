import { useState } from "react";

export function TeardownPanel({ disabled, onDelete }: { disabled: boolean; onDelete: () => void }) {
  const [armed, setArmed] = useState(false);

  const handleClick = () => {
    if (!armed) {
      setArmed(true);
      return;
    }
    setArmed(false);
    onDelete();
  };

  return (
    <button className="launchpad-action launchpad-action-danger" type="button" disabled={disabled} onClick={handleClick}>
      {armed ? "Confirm delete" : "Delete"}
    </button>
  );
}
