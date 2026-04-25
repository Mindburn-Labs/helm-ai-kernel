import { TruthState } from "./domain";

export interface ApprovalCeremonyState {
  approvalId: string;
  intentHash: string;
  uiSummaryHash: string;
  timeLockRemainingMs: number;
  reentryRequired: boolean;
  holdDurationMs: number;
  truthState: TruthState;
}
