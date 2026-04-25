import { create } from 'zustand';
import type { QueueStatus, SelfModClass } from './types';

interface SkillsStore {
  selectedCandidateId: string | null;
  filterQueueStatus: QueueStatus | null;
  filterSelfModClass: SelfModClass | null;
  setSelectedCandidate: (id: string | null) => void;
  setFilterQueueStatus: (status: QueueStatus | null) => void;
  setFilterSelfModClass: (cls: SelfModClass | null) => void;
}

export const useSkillsStore = create<SkillsStore>((set) => ({
  selectedCandidateId: null,
  filterQueueStatus: null,
  filterSelfModClass: null,
  setSelectedCandidate: (id) => set({ selectedCandidateId: id }),
  setFilterQueueStatus: (status) => set({ filterQueueStatus: status }),
  setFilterSelfModClass: (cls) => set({ filterSelfModClass: cls }),
}));
