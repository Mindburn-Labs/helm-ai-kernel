import { create } from 'zustand';
import type { RiskClass } from './types';

interface ActionInboxStore {
  selectedProposalId: string | null;
  filterStatus: string | null;
  filterRiskClass: RiskClass | null;
  filterProgramId: string | null;
  sortBy: 'priority' | 'created_at' | 'risk_class';
  selectedForBatch: Set<string>;
  setSelectedProposal: (id: string | null) => void;
  setFilterStatus: (status: string | null) => void;
  setFilterRiskClass: (rc: RiskClass | null) => void;
  setFilterProgramId: (id: string | null) => void;
  setSortBy: (sort: 'priority' | 'created_at' | 'risk_class') => void;
  toggleBatchSelect: (id: string) => void;
  clearBatchSelection: () => void;
  selectAllForBatch: (ids: string[]) => void;
}

export const useActionInboxStore = create<ActionInboxStore>((set) => ({
  selectedProposalId: null,
  filterStatus: null,
  filterRiskClass: null,
  filterProgramId: null,
  sortBy: 'priority',
  selectedForBatch: new Set(),
  setSelectedProposal: (id) => set({ selectedProposalId: id }),
  setFilterStatus: (status) => set({ filterStatus: status }),
  setFilterRiskClass: (rc) => set({ filterRiskClass: rc }),
  setFilterProgramId: (id) => set({ filterProgramId: id }),
  setSortBy: (sort) => set({ sortBy: sort }),
  toggleBatchSelect: (id) =>
    set((state) => {
      const next = new Set(state.selectedForBatch);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return { selectedForBatch: next };
    }),
  clearBatchSelection: () => set({ selectedForBatch: new Set() }),
  selectAllForBatch: (ids) => set({ selectedForBatch: new Set(ids) }),
}));
