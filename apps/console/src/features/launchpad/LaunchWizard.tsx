import { ArrowLeft, ArrowRight, Play, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { ProofPanel } from "./ProofPanel";
import {
  appKey,
  entitlementAllows,
  launchBlockedReasons,
  secretRequirements,
  type SecretRequirement,
} from "./model";
import type {
  LaunchpadApp,
  LaunchpadMatrixCell,
  LaunchpadPlanResponse,
  LaunchpadRunDetail,
  LaunchpadSecretGrant,
  LaunchpadSubstrate,
  MCPThreatReview,
} from "./types";

export function LaunchWizard({
  apps,
  substrates,
  matrix,
  secrets,
  threatReviews,
  selectedApp,
  selectedSubstrate,
  plan,
  detail,
  busy,
  onSelectApp,
  onSelectSubstrate,
  onPreflight,
  onLaunch,
  onBindSecret,
}: {
  readonly apps: readonly LaunchpadApp[];
  readonly substrates: readonly LaunchpadSubstrate[];
  readonly matrix: readonly LaunchpadMatrixCell[];
  readonly secrets: readonly LaunchpadSecretGrant[];
  readonly threatReviews: readonly MCPThreatReview[];
  readonly selectedApp: string;
  readonly selectedSubstrate: string;
  readonly plan: LaunchpadPlanResponse | null;
  readonly detail: LaunchpadRunDetail | null;
  readonly busy: boolean;
  readonly onSelectApp: (id: string) => void;
  readonly onSelectSubstrate: (id: string) => void;
  readonly onPreflight: (id: string) => void;
  readonly onLaunch: (id: string) => void;
  readonly onBindSecret: (requirement: SecretRequirement) => void;
}) {
  const [step, setStep] = useState(1);
  const totalSteps = 5;
  const app = useMemo(() => apps.find((item) => appKey(item) === selectedApp) ?? apps[0], [apps, selectedApp]);
  const substrate = useMemo(() => substrates.find((item) => item.id === selectedSubstrate) ?? substrates[0], [substrates, selectedSubstrate]);
  const requirements = useMemo(() => app ? secretRequirements(app, secrets) : [], [app, secrets]);
  const missing = useMemo(() => requirements.filter((requirement) => {
    return !requirement.present || app?.status?.missing_secrets?.includes(requirement.env) || app?.status?.missing_secrets?.includes(requirement.logical);
  }), [app, requirements]);
  const appReviews = useMemo(() => app ? threatReviews.filter((review) => review.app_id === appKey(app)) : [], [app, threatReviews]);
  const cell = useMemo(() => app && substrate ? matrix.find((entry) => entry.app_id === appKey(app) && entry.substrate_id === substrate.id) : undefined, [app, substrate, matrix]);
  const blocked = app ? launchBlockedReasons(app, cell, missing, appReviews) : ["No app selected."];
  const canLaunch = Boolean(app && substrate && blocked.length === 0 && entitlementAllows(app, "launch"));
  const appName = app?.name ?? "Select an app";

  return (
    <section className="simple-wizard-container">
      <div className="wizard-steps" role="navigation" aria-label="Launch steps">
        {Array.from({ length: totalSteps }, (_, index) => (
          <button
            type="button"
            key={index + 1}
            className={`wizard-step ${step === index + 1 ? "active" : step > index + 1 ? "completed" : ""}`}
            aria-current={step === index + 1 ? "step" : undefined}
            onClick={() => setStep(index + 1)}
          >
            {step > index + 1 ? "✓" : index + 1}
          </button>
        ))}
      </div>

      <div className="simple-wizard-card">
        {step === 1 ? (
          <>
            <Header title="Choose an app" body="The catalog is loaded from the Launchpad registry API." />
            <div className="simple-option-grid" aria-label="Select application to launch">
              {apps.map((item) => {
                const id = appKey(item);
                const selected = appKey(app ?? item) === id;
                return (
                  <button type="button" key={id} className={`simple-option-card ${selected ? "selected" : ""}`} onClick={() => onSelectApp(id)}>
                    <strong>{item.name}</strong>
                    <span>{item.status?.summary ?? item.availability ?? "Backend status unavailable."}</span>
                    <em>{selected ? "Selected" : "Select"}</em>
                  </button>
                );
              })}
            </div>
          </>
        ) : null}

        {step === 2 ? (
          <>
            <Header title="Choose a runtime" body="Substrates come from the Launchpad substrate API and matrix." />
            <div className="simple-option-grid" aria-label="Select runtime substrate">
              {substrates.map((item) => (
                <button type="button" key={item.id} className={`simple-option-card ${selectedSubstrate === item.id ? "selected" : ""}`} onClick={() => onSelectSubstrate(item.id)}>
                  <strong>{item.name}</strong>
                  <span>{item.kind || item.id}</span>
                  <em>{item.availability}</em>
                </button>
              ))}
            </div>
          </>
        ) : null}

        {step === 3 ? (
          <>
            <Header title="Set up required secrets" body="The Console binds environment variable names only. It never collects raw secret values." />
            {missing.length === 0 ? (
              <div className="simple-safety-card">
                <div className="simple-safety-card-icon"><ShieldCheck className="state-allow" size={24} /></div>
                <div className="simple-safety-card-content">
                  <strong>No missing secret grants</strong>
                  <p>Backend status reports that this selection can continue past secret preflight.</p>
                </div>
              </div>
            ) : (
              <div className="secret-fix-panel">
                <strong>Environment variable required</strong>
                <p>Set the env var in the Kernel process, then bind the env name below.</p>
                {missing.map((requirement) => (
                  <div key={`${requirement.logical}:${requirement.env}`} className="secret-fix-row">
                    <code>{requirement.cli}</code>
                    <button className="launchpad-action" type="button" disabled={busy} onClick={() => onBindSecret(requirement)}>Bind env</button>
                  </div>
                ))}
              </div>
            )}
          </>
        ) : null}

        {step === 4 ? (
          <>
            <Header title="Run preflight" body="Preflight compiles a LaunchPlan without starting runtime side effects." />
            <dl className="launchpad-facts">
              <Fact label="App" value={appName} />
              <Fact label="Substrate" value={substrate?.name ?? "unselected"} />
              <Fact label="Matrix" value={cell ? `${cell.verdict} - ${cell.reason}` : "unproven"} />
              <Fact label="LaunchPlan" value={plan?.plan_hash ?? "not compiled"} />
              <Fact label="Verdict" value={plan?.kernel_verdict ?? "not compiled"} />
            </dl>
            {blocked.length > 0 ? <div className="inline-error">{blocked.join(" ")}</div> : null}
            <button className="launchpad-action launchpad-action-primary" type="button" disabled={busy || !app || !substrate} onClick={() => app && onPreflight(appKey(app))}>
              Preflight
            </button>
          </>
        ) : null}

        {step === 5 ? (
          <>
            <Header title="Launch and verify" body="Runtime starts only when backend gates permit it. Proof remains visible for every result." />
            <button className="primary-action launchpad-action" type="button" disabled={busy || !canLaunch || !app} onClick={() => app && onLaunch(appKey(app))}>
              <Play size={18} aria-hidden="true" /> Launch Safely
            </button>
            <ProofPanel plan={plan} detail={detail} />
          </>
        ) : null}

        <div className="wizard-actions">
          <button type="button" className="secondary-action launchpad-action" onClick={() => setStep((current) => Math.max(1, current - 1))} disabled={step === 1}>
            <ArrowLeft size={14} /> Back
          </button>
          <button type="button" className="primary-action launchpad-action" onClick={() => setStep((current) => Math.min(totalSteps, current + 1))} disabled={step === totalSteps}>
            Next <ArrowRight size={14} />
          </button>
        </div>
      </div>
    </section>
  );
}

function Header({ title, body }: { readonly title: string; readonly body: string }) {
  return (
    <div className="simple-wizard-header">
      <h3>{title}</h3>
      <p>{body}</p>
    </div>
  );
}

function Fact({ label, value }: { readonly label: string; readonly value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}
