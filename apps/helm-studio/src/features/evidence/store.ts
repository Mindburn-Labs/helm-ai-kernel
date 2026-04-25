import { create } from 'zustand';
import type { ExportFormat, ExportStatus } from './types';

interface EvidenceStore {
  selectedJobId: string | null;
  filterStatus: ExportStatus | null;
  selectedRunId: string | null;
  exportFormat: ExportFormat;
  setSelectedJob: (id: string | null) => void;
  setFilterStatus: (status: ExportStatus | null) => void;
  setSelectedRunId: (runId: string | null) => void;
  setExportFormat: (format: ExportFormat) => void;
}

export const useEvidenceStore = create<EvidenceStore>((set) => ({
  selectedJobId: null,
  filterStatus: null,
  selectedRunId: null,
  exportFormat: 'json',
  setSelectedJob: (id) => set({ selectedJobId: id }),
  setFilterStatus: (status) => set({ filterStatus: status }),
  setSelectedRunId: (runId) => set({ selectedRunId: runId }),
  setExportFormat: (format) => set({ exportFormat: format }),
}));
