export type StoreClass = 'lks' | 'cks';
export type ClaimStatus = 'pending' | 'approved' | 'rejected';

export interface KnowledgeClaim {
  id: string;
  workspaceId: string;
  title: string;
  body: string;
  storeClass: StoreClass;
  provenanceScore: number;
  dualSourceRequired: boolean;
  approvalRequired: boolean;
  status: ClaimStatus;
  sourceRefs: string[];
  createdAt: string;
}

export interface PromoteClaimRequest {
  claimId: string;
  targetStoreClass: StoreClass;
}
