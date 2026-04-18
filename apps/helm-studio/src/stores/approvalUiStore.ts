import { create } from "zustand";
import { ApprovalCeremonyState } from "../types/approval";

interface ApprovalUiState {
  ceremonyStep: "review" | "auth" | "confirm" | "done";
  holdToApproveTimerMs: number;
  transientConfirmationInput: string;
  ceremonyState: ApprovalCeremonyState | null;

  setCeremonyStep: (step: "review" | "auth" | "confirm" | "done") => void;
  setCeremonyState: (state: ApprovalCeremonyState | null) => void;
  updateTimer: (ms: number) => void;
  setConfirmationInput: (val: string) => void;
}

export const useApprovalUiStore = create<ApprovalUiState>((set) => ({
  ceremonyStep: "review",
  holdToApproveTimerMs: 0,
  transientConfirmationInput: "",
  ceremonyState: null,

  setCeremonyStep: (step) => set({ ceremonyStep: step }),
  setCeremonyState: (state) => set({ ceremonyState: state }),
  updateTimer: (ms) => set({ holdToApproveTimerMs: ms }),
  setConfirmationInput: (val) => set({ transientConfirmationInput: val }),
}));
