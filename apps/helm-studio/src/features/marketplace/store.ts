import { create } from 'zustand';
import type { ConnectorState } from './types';

interface MarketplaceStore {
  selectedConnectorId: string | null;
  filterState: ConnectorState | null;
  searchQuery: string;
  setSelectedConnector: (id: string | null) => void;
  setFilterState: (state: ConnectorState | null) => void;
  setSearchQuery: (query: string) => void;
}

export const useMarketplaceStore = create<MarketplaceStore>((set) => ({
  selectedConnectorId: null,
  filterState: null,
  searchQuery: '',
  setSelectedConnector: (id) => set({ selectedConnectorId: id }),
  setFilterState: (state) => set({ filterState: state }),
  setSearchQuery: (query) => set({ searchQuery: query }),
}));
