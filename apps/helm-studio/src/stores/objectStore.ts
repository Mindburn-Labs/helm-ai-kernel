import { create } from "zustand";
import { ObjectRef } from "../types/domain";

interface ObjectState {
  activeObjectRefs: ObjectRef[];
  selectedObjectGraphEdges: Array<Record<string, unknown>>;
  localDraftTabs: Array<Record<string, unknown>>;
  pinnedObjects: ObjectRef[];

  setActiveObject: (ref: ObjectRef) => void;
  pinObject: (ref: ObjectRef) => void;
}

export const useObjectStore = create<ObjectState>((set) => ({
  activeObjectRefs: [],
  selectedObjectGraphEdges: [],
  localDraftTabs: [],
  pinnedObjects: [],

  setActiveObject: (ref) =>
    set((state) => ({ activeObjectRefs: [...state.activeObjectRefs, ref] })),
  pinObject: (ref) =>
    set((state) => ({ pinnedObjects: [...state.pinnedObjects, ref] })),
}));
