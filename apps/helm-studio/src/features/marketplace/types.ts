export type ConnectorState = 'candidate' | 'certified' | 'revoked';

export interface MarketplaceConnector {
  id: string;
  name: string;
  version: string;
  state: ConnectorState;
  badges: string[];
  certificationRef?: string;
  lastVerifiedAt?: string;
}

export interface ConnectorVersion {
  version: string;
  state: ConnectorState;
  releasedAt: string;
  certificationRef?: string;
}
