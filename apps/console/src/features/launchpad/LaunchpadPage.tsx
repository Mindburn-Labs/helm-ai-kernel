import { AlertTriangle, Play, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { launchpadApi } from "./api";
import { AppPicker } from "./AppPicker";
import { GrantReviewPanel } from "./GrantReviewPanel";
import { LaunchMatrix } from "./LaunchMatrix";
import { LaunchReceiptsPanel } from "./LaunchReceiptsPanel";
import { LaunchStatusPanel } from "./LaunchStatusPanel";
import { McpQuarantinePanel } from "./McpQuarantinePanel";
import { PolicyPackPanel } from "./PolicyPackPanel";
import { RepairPanel } from "./RepairPanel";
import { SubstratePicker } from "./SubstratePicker";
import { TeardownPanel } from "./TeardownPanel";
import type { LaunchpadApp, LaunchpadMatrixCell, LaunchpadPlanResponse, LaunchpadRun, LaunchpadSubstrate } from "./types";

export function LaunchpadPage() {
  const [apps, setApps] = useState<LaunchpadApp[]>([]);
  const [substrates, setSubstrates] = useState<LaunchpadSubstrate[]>([]);
  const [matrix, setMatrix] = useState<LaunchpadMatrixCell[]>([]);
  const [selectedApp, setSelectedApp] = useState("");
  const [selectedSubstrate, setSelectedSubstrate] = useState("");
  const [plan, setPlan] = useState<LaunchpadPlanResponse | null>(null);
  const [run, setRun] = useState<LaunchpadRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    setError(null);
    try {
      const [nextApps, nextSubstrates, nextMatrix] = await Promise.all([
        launchpadApi.apps(),
        launchpadApi.substrates(),
        launchpadApi.matrix(),
      ]);
      setApps(nextApps);
      setSubstrates(nextSubstrates);
      setMatrix(nextMatrix);
      setSelectedApp((current) => current || nextApps[0]?.id || "");
      setSelectedSubstrate((current) => current || nextSubstrates.find((item) => item.id === "local-container")?.id || nextSubstrates[0]?.id || "");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Launchpad API unavailable");
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const app = useMemo(() => apps.find((item) => item.id === selectedApp), [apps, selectedApp]);
  const substrate = useMemo(() => substrates.find((item) => item.id === selectedSubstrate), [substrates, selectedSubstrate]);
  const launchId = run?.launch_id ?? run?.id ?? plan?.launch_id;

  const execute = async (kind: "plan" | "launch" | "repair" | "delete") => {
    if (!selectedApp || !selectedSubstrate) return;
    setBusy(true);
    setError(null);
    try {
      if (kind === "plan") setPlan(await launchpadApi.plan(selectedApp, selectedSubstrate));
      if (kind === "launch") setRun(await launchpadApi.launch(selectedApp, selectedSubstrate));
      if (kind === "repair" && launchId) await launchpadApi.repair(launchId);
      if (kind === "delete" && launchId) setRun(await launchpadApi.delete(launchId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Launchpad action failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="launchpad-surface">
      <section className="launchpad-panel launchpad-hero">
        <div>
          <span className="eyebrow">launchpad</span>
          <h2>Fail-closed app launcher</h2>
          <p>API-backed matrix, policy review, MCP quarantine, receipts, EvidencePack refs, repair, and teardown.</p>
        </div>
        <button className="launchpad-action" type="button" onClick={() => void load()}>
          <RefreshCw size={14} /> Refresh
        </button>
      </section>
      {error ? (
        <div className="inline-error" role="alert">
          <AlertTriangle size={14} /> {error}
        </div>
      ) : null}
      <section className="launchpad-panel">
        <div className="launchpad-controls">
          <AppPicker apps={apps} selected={selectedApp} onSelect={setSelectedApp} />
          <SubstratePicker substrates={substrates} selected={selectedSubstrate} onSelect={setSelectedSubstrate} />
          <button className="launchpad-action" type="button" disabled={busy || !selectedApp || !selectedSubstrate} onClick={() => void execute("plan")}>Plan</button>
          <button className="launchpad-action" type="button" disabled={busy || !selectedApp || !selectedSubstrate} onClick={() => void execute("launch")}><Play size={14} /> Launch</button>
          <RepairPanel disabled={busy || !launchId} onRepair={() => void execute("repair")} />
          <TeardownPanel disabled={busy || !launchId} onDelete={() => void execute("delete")} />
        </div>
      </section>
      <div className="launchpad-grid">
        <PolicyPackPanel app={app} substrate={substrate} />
        <GrantReviewPanel app={app} substrate={substrate} />
        <McpQuarantinePanel />
        <LaunchStatusPanel plan={plan} run={run} />
        <LaunchReceiptsPanel plan={plan} run={run} />
      </div>
      <LaunchMatrix matrix={matrix} />
    </div>
  );
}
