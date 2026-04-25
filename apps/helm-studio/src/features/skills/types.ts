export type SelfModClass = 'C0' | 'C1' | 'C2' | 'C3';
export type EvaluationVerdict = 'pass' | 'fail' | 'needs_review';
export type QueueStatus = 'queued' | 'evaluating' | 'ready' | 'promoted' | 'rejected';

export interface SkillCandidate {
  id: string;
  workspaceId: string;
  skillId: string;
  name: string;
  version: string;
  selfModClass: SelfModClass;
  evaluationVerdict: EvaluationVerdict;
  queueStatus: QueueStatus;
  createdAt: string;
}

export interface InstalledSkill {
  id: string;
  workspaceId: string;
  skillId: string;
  name: string;
  version: string;
  selfModClass: SelfModClass;
  installedAt: string;
  status: 'active' | 'inactive' | 'deprecated';
}
