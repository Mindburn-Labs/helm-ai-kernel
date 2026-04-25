import { create } from 'zustand';
import type { ClaimStatus, StoreClass } from './types';

interface KnowledgeStore {
  selectedClaimId: string | null;
  selectedStoreClass: StoreClass;
  filterStatus: ClaimStatus | null;
  setSelectedClaim: (id: string | null) => void;
  setSelectedStoreClass: (storeClass: StoreClass) => void;
  setFilterStatus: (status: ClaimStatus | null) => void;
}

export const useKnowledgeStore = create<KnowledgeStore>((set) => ({
  selectedClaimId: null,
  selectedStoreClass: 'lks',
  filterStatus: null,
  setSelectedClaim: (id) => set({ selectedClaimId: id }),
  setSelectedStoreClass: (storeClass) => set({ selectedStoreClass: storeClass }),
  setFilterStatus: (status) => set({ filterStatus: status }),
}));
