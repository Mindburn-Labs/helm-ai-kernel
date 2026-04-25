import { create } from "zustand";

interface EvidenceState {
  activeSourceTab: string;
  receiptExpansionState: Record<string, boolean>;
  setActiveTab: (tab: string) => void;
  toggleReceipt: (id: string) => void;
}

export const useEvidencePaneStore = create<EvidenceState>((set) => ({
  activeSourceTab: 'sources',
  receiptExpansionState: {},
  setActiveTab: (tab) => set({ activeSourceTab: tab }),
  toggleReceipt: (id) => set((state) => ({ 
    receiptExpansionState: { ...state.receiptExpansionState, [id]: !state.receiptExpansionState[id] } 
  }))
}));
