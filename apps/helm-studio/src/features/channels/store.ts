import { create } from 'zustand';
import type { ChannelType, SessionStatus } from './types';

interface ChannelsStore {
  selectedSessionId: string | null;
  filterChannel: ChannelType | null;
  filterStatus: SessionStatus | null;
  setSelectedSession: (id: string | null) => void;
  setFilterChannel: (channel: ChannelType | null) => void;
  setFilterStatus: (status: SessionStatus | null) => void;
}

export const useChannelsStore = create<ChannelsStore>((set) => ({
  selectedSessionId: null,
  filterChannel: null,
  filterStatus: null,
  setSelectedSession: (id) => set({ selectedSessionId: id }),
  setFilterChannel: (channel) => set({ filterChannel: channel }),
  setFilterStatus: (status) => set({ filterStatus: status }),
}));
