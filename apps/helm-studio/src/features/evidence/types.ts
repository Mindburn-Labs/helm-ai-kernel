export type ExportStatus = 'pending' | 'exporting' | 'completed' | 'failed';
export type ExportFormat = 'json' | 'protobuf';

export interface EvidenceExportJob {
  id: string;
  workspaceId: string;
  status: ExportStatus;
  format: ExportFormat;
  runIds: string[];
  outputRef?: string;
  createdAt: string;
  completedAt?: string;
}

export interface ProofGraphNode {
  id: string;
  type: string;
  label: string;
  parentIds: string[];
  hash: string;
  createdAt: string;
}

export interface CreateExportRequest {
  format: ExportFormat;
  runIds: string[];
}
