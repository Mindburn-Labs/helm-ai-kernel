import { create } from "zustand";
import { Mode } from "../types/domain";

interface ShellState {
  activeMode: Mode | null;
  chatDrawerOpen: boolean;
  rightPaneOpen: boolean;
  bottomRailExpanded: boolean;
  commandPaletteOpen: boolean;

  setMode: (mode: Mode) => void;
  toggleChatDrawer: () => void;
  toggleRightPane: () => void;
  toggleBottomRail: () => void;
  setCommandPaletteOpen: (open: boolean) => void;
}

export const useShellStore = create<ShellState>((set) => ({
  activeMode: null,
  chatDrawerOpen: false,
  rightPaneOpen: false,
  bottomRailExpanded: false,
  commandPaletteOpen: false,

  setMode: (mode) => set({ activeMode: mode }),
  toggleChatDrawer: () => set((state) => ({ chatDrawerOpen: !state.chatDrawerOpen })),
  toggleRightPane: () => set((state) => ({ rightPaneOpen: !state.rightPaneOpen })),
  toggleBottomRail: () => set((state) => ({ bottomRailExpanded: !state.bottomRailExpanded })),
  setCommandPaletteOpen: (open) => set({ commandPaletteOpen: open }),
}));
