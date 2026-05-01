"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

/**
 * `AnnounceProvider` — mounts two visually-hidden `aria-live` regions
 * (polite + assertive) shared across the app, exposes a `useAnnounce()`
 * hook for any component to push a status update, and rotates DOM text
 * so identical-string repeats still announce on every call.
 *
 * Deliberately separate from `Toaster` (which is visible UI) — this is
 * an invisible AT-only channel for status updates ("Filter applied, 3
 * results", "Action denied", "Saved").
 */

export type AnnouncePoliteness = "polite" | "assertive";

export interface AnnounceContextValue {
  /** Push a message to the polite region. */
  readonly announce: (message: string) => void;
  /** Push a message to the assertive region (rare; for blocking errors). */
  readonly announceUrgent: (message: string) => void;
}

const AnnounceContext = createContext<AnnounceContextValue | null>(null);

/**
 * Returns `{ announce, announceUrgent }` when used under `AnnounceProvider`,
 * `null` otherwise. Components should treat null as "no AT channel
 * available; degrade gracefully" rather than throw.
 */
export function useAnnounce(): AnnounceContextValue | null {
  return useContext(AnnounceContext);
}

interface SlotState {
  readonly message: string;
  readonly nonce: number;
}

const EMPTY: SlotState = { message: "", nonce: 0 };

export function AnnounceProvider({ children }: { readonly children: ReactNode }) {
  const [polite, setPolite] = useState<SlotState>(EMPTY);
  const [assertive, setAssertive] = useState<SlotState>(EMPTY);
  const nonceRef = useRef(0);

  const enqueue = useCallback((politeness: AnnouncePoliteness, message: string) => {
    if (!message) return;
    nonceRef.current += 1;
    const next: SlotState = { message, nonce: nonceRef.current };
    if (politeness === "assertive") setAssertive(next);
    else setPolite(next);
  }, []);

  const announce = useCallback((message: string) => enqueue("polite", message), [enqueue]);
  const announceUrgent = useCallback((message: string) => enqueue("assertive", message), [enqueue]);

  // Clear after a short delay so the region empties and is ready for
  // the next message (some AT clients suppress duplicate announcements
  // unless the node empties between updates).
  useEffect(() => {
    if (polite.message === "") return undefined;
    const timer = setTimeout(() => setPolite({ message: "", nonce: polite.nonce }), 1500);
    return () => clearTimeout(timer);
  }, [polite]);
  useEffect(() => {
    if (assertive.message === "") return undefined;
    const timer = setTimeout(() => setAssertive({ message: "", nonce: assertive.nonce }), 1500);
    return () => clearTimeout(timer);
  }, [assertive]);

  const value = useMemo<AnnounceContextValue>(
    () => ({ announce, announceUrgent }),
    [announce, announceUrgent],
  );

  return (
    <AnnounceContext.Provider value={value}>
      {children}
      <div className="sr-only" role="status" aria-live="polite" aria-atomic="true" data-nonce={polite.nonce}>
        {polite.message}
      </div>
      <div className="sr-only" role="alert" aria-live="assertive" aria-atomic="true" data-nonce={assertive.nonce}>
        {assertive.message}
      </div>
    </AnnounceContext.Provider>
  );
}
