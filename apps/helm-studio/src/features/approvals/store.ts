import { create } from 'zustand';

interface ApprovalsStore {
  selectedCeremonyId: string | null;
  filterStatus: 'pending' | 'in_progress' | 'completed' | 'expired' | null;
  setSelectedCeremony: (id: string | null) => void;
  setFilterStatus: (status: 'pending' | 'in_progress' | 'completed' | 'expired' | null) => void;
}

export const useApprovalsStore = create<ApprovalsStore>((set) => ({
  selectedCeremonyId: null,
  filterStatus: 'pending',
  setSelectedCeremony: (id) => set({ selectedCeremonyId: id }),
  setFilterStatus: (status) => set({ filterStatus: status }),
}));
