"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  type ReactNode,
} from "react";

/**
 * Opt-in telemetry surface — `<TelemetryProvider>` collects component
 * mount + interaction events through a sink the consumer plugs in.
 * No defaults, no transitive dep on any analytics SDK; the system
 * stays neutral and lets the platform team route to their own pipeline.
 *
 *     <TelemetryProvider sink={(event) => myAnalytics.track(event.name, event.props)}>
 *       <App />
 *     </TelemetryProvider>
 *
 * Primitives that want to be observable call `useTelemetry()` and
 * fire events on mount / interaction. Outside a provider, the hook
 * returns a no-op so nothing leaks.
 */

export interface TelemetryEvent {
  readonly name: string;
  readonly props?: Readonly<Record<string, unknown>>;
  /** `Date.now()` epoch-ms at emission. */
  readonly ts: number;
}

export type TelemetrySink = (event: TelemetryEvent) => void;

export interface TelemetryContextValue {
  readonly emit: (name: string, props?: Readonly<Record<string, unknown>>) => void;
}

const NOOP: TelemetryContextValue = { emit: () => {} };
const TelemetryContext = createContext<TelemetryContextValue>(NOOP);

export function useTelemetry(): TelemetryContextValue {
  return useContext(TelemetryContext);
}

/**
 * Convenience hook: emit a single `${name}.mount` event the first time
 * a component mounts. Pass a stable `props` object (or memoize at the
 * call site) — the hook intentionally ignores prop changes after mount.
 */
export function useTelemetryMount(name: string, props?: Readonly<Record<string, unknown>>) {
  const { emit } = useTelemetry();
  useEffect(() => {
    if (typeof window === "undefined") return undefined;
    let fired = false;
    const handle = window.requestAnimationFrame(() => {
      if (fired) return;
      fired = true;
      emit(`${name}.mount`, props);
    });
    return () => window.cancelAnimationFrame(handle);
    // Mount-once: deliberately omit prop deps.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
}

export interface TelemetryProviderProps {
  readonly children: ReactNode;
  readonly sink: TelemetrySink;
  /** When true, also `console.debug` every event. */
  readonly debug?: boolean;
}

export function TelemetryProvider({ children, sink, debug = false }: TelemetryProviderProps) {
  const emit = useCallback(
    (name: string, props?: Readonly<Record<string, unknown>>) => {
      const event: TelemetryEvent = { name, props, ts: Date.now() };
      try {
        sink(event);
      } catch (error) {
        if (debug) console.error("[helm-telemetry] sink threw:", error);
      }
      if (debug) console.debug("[helm-telemetry]", event);
    },
    [sink, debug],
  );

  const value = useMemo<TelemetryContextValue>(() => ({ emit }), [emit]);
  return <TelemetryContext.Provider value={value}>{children}</TelemetryContext.Provider>;
}
