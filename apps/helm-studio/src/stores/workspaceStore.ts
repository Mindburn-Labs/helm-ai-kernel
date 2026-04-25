import { create } from "zustand";
import { Mode, WorkspaceContext } from "../types/domain";

interface WorkspaceState {
  workspaces: WorkspaceContext[];
  activeWorkspaceId: string | null;
  savedViews: Record<string, Array<Record<string, unknown>>>;
  setActiveWorkspace: (id: string) => void;
  updateWorkspaceMode: (id: string, mode: Mode) => void;
}

export const useWorkspaceStore = create<WorkspaceState>((set) => ({
  workspaces: [],
  activeWorkspaceId: null,
  savedViews: {},
  setActiveWorkspace: (id) => set({ activeWorkspaceId: id }),
  updateWorkspaceMode: (id, mode) =>
    set((state) => ({
      workspaces: state.workspaces.map((w) =>
        w.id === id ? { ...w, mode } : w
      ),
    })),
}));
