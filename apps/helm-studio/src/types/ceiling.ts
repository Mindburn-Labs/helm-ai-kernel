export interface CeilingSet {
  id: string;
  workspaceId: string;
  truthState: "pending" | "active" | "revoked";
  effectiveAt?: string;
  expiresAt?: string;
  emergencyOverride: boolean;
}
