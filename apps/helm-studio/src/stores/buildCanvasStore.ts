import { create } from 'zustand';

interface BuildCanvasState {
  selectedNodeId: string | null;
  setSelectedNodeId: (id: string | null) => void;
}

export const useBuildCanvasStore = create<BuildCanvasState>((set) => ({
  selectedNodeId: null,
  setSelectedNodeId: (id) => set({ selectedNodeId: id })
}));
