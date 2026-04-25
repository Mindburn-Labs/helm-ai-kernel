import { create } from 'zustand';

interface RunSupervisorState {
  focusedRunId: string | null;
  setFocusedRunId: (id: string | null) => void;
}

export const useRunSupervisorStore = create<RunSupervisorState>((set) => ({
  focusedRunId: null,
  setFocusedRunId: (id) => set({ focusedRunId: id })
}));
