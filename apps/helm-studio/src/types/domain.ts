export type Surface = 'canvas' | 'operate' | 'research' | 'govern' | 'proof' | 'chat';

export type Mode =
  | Surface
  | 'investigate'
  | 'build'
  | 'replay'
  | 'integrations'
  | 'integrate';

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export type TruthStage =
  | 'proposed'
  | 'draft'
  | 'active'
  | 'approved'
  | 'running'
  | 'blocked'
  | 'completed'
  | 'verified'
  | 'unverified';

export type TruthState =
  | 'draft'
  | 'pending'
  | 'attested'
  | 'executed'
  | 'blocked'
  | 'replayed'
  | 'stale'
  | 'active';

export type EnvironmentLabel = 'local' | 'staging' | 'production';

export interface WorkspaceContext {
  id: string;
  name: string;
  slug?: string;
  edition?: string;
  offerCode?: string;
  mode?: string;
  profile?: string;
  status?: string;
  environment?: EnvironmentLabel;
  scopeLabel?: string;
  createdAt?: string;
  updatedAt?: string;
  source?: 'controlplane' | 'studio';
}

export interface ObjectRef {
  id: string;
  kind: string;
  workspaceId: string;
}
