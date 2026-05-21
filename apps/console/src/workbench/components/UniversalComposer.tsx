import { type RefObject } from "react";
import { AlertCircle } from "lucide-react";
import {
  Button,
  WorkbenchComposer,
  WorkbenchQuickActions,
  WorkbenchQuickAction,
} from "@mindburn/ui-core";
import type { WorkbenchSnapshot, QuickAction } from "../types";

export interface UniversalComposerProps {
  readonly snapshot: WorkbenchSnapshot;
  readonly commandText: string;
  readonly principal: string;
  readonly submitting: boolean;
  readonly actionError: string | null;
  readonly refreshing: boolean;
  readonly composerRef: RefObject<HTMLTextAreaElement | null>;
  readonly onCommandChange: (value: string) => void;
  readonly onPrincipalChange: (value: string) => void;
  readonly onSubmit: () => void;
  readonly onQuickAction: (action: QuickAction) => void;
  readonly onRefresh: () => void;
}

function InlineError({ message }: { readonly message: string }) {
  return (
    <p className="inline-error" role="alert">
      <AlertCircle size={14} aria-hidden />
      {message}
    </p>
  );
}

export function UniversalComposer({
  snapshot,
  commandText,
  principal,
  submitting,
  actionError,
  refreshing,
  composerRef,
  onCommandChange,
  onPrincipalChange,
  onSubmit,
  onQuickAction,
  onRefresh,
}: UniversalComposerProps) {
  return (
    <>
      <WorkbenchComposer
        title="Governed agent cockpit"
        body="Start with one intent. HELM evaluates policy, records proof, and exposes approvals, replay, evidence, and runtime capabilities only when they matter."
        principal={principal}
        command={commandText}
        busy={submitting}
        commandRef={composerRef}
        error={actionError ? <InlineError message={actionError} /> : null}
        onPrincipalChange={onPrincipalChange}
        onCommandChange={onCommandChange}
        onSubmit={onSubmit}
        secondaryAction={
          <Button
            variant="secondary"
            disabled={refreshing}
            onClick={onRefresh}
          >
            {refreshing ? "Refreshing" : "Refresh"}
          </Button>
        }
      />

      <WorkbenchQuickActions>
        {snapshot.quickActions.map((action) => (
          <WorkbenchQuickAction
            key={action.id}
            label={action.label}
            hint={action.hint}
            onClick={() => onQuickAction(action)}
          />
        ))}
      </WorkbenchQuickActions>
    </>
  );
}
