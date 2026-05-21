import { useCallback, useEffect, useState } from "react";
import { ADMIN_SURFACES, type AdminSurfaceConfig } from "../admin/surfaces";
import {
  isUnauthorizedError,
  loadBootstrap,
  loadConsoleSurfaceCatalog,
  loadReceipts,
  watchReceipts,
  type AdminRecord,
  type ConsoleBootstrap,
  type Receipt,
} from "../api/client";
import { buildCapabilities, isRecord, receiptKey, type CapabilitySnapshot } from "./viewModels";

export type ConsoleAccessState = "unknown" | "authorized" | "unauthorized";
export type ReceiptStreamState = "connecting" | "live" | "disconnected" | "unauthorized";

const DEFAULT_SURFACE_CONFIGS: readonly AdminSurfaceConfig[] = Object.values(ADMIN_SURFACES);

function configsFromCatalog(surfaceIds: readonly string[]): readonly AdminSurfaceConfig[] {
  if (surfaceIds.length === 0) return DEFAULT_SURFACE_CONFIGS;
  const seen = new Set<string>();
  const ordered: AdminSurfaceConfig[] = [];
  for (const id of surfaceIds) {
    const config = ADMIN_SURFACES[id];
    if (config && !seen.has(id)) {
      ordered.push(config);
      seen.add(id);
    }
  }
  for (const config of DEFAULT_SURFACE_CONFIGS) {
    if (!seen.has(config.id)) ordered.push(config);
  }
  return ordered;
}

function isSortedByLamportDesc(receipts: readonly Receipt[]): boolean {
  for (let index = 1; index < receipts.length; index += 1) {
    if ((receipts[index - 1]?.lamport_clock ?? 0) < (receipts[index]?.lamport_clock ?? 0)) return false;
  }
  return true;
}

function mergeReceiptBatch(current: readonly Receipt[], next: readonly Receipt[]): readonly Receipt[] {
  const map = new Map<string, Receipt>();
  for (const receipt of current) map.set(receiptKey(receipt), receipt);
  for (const receipt of next) map.set(receiptKey(receipt), receipt);
  return [...map.values()].sort((a, b) => (b.lamport_clock ?? 0) - (a.lamport_clock ?? 0)).slice(0, 200);
}

export function mergeReceipts(current: readonly Receipt[], next: readonly Receipt[]): readonly Receipt[] {
  if (next.length !== 1 || !isSortedByLamportDesc(current)) return mergeReceiptBatch(current, next);
  const receipt = next[0];
  const key = receiptKey(receipt);
  const entries: Array<{ readonly receipt: Receipt; readonly originalIndex: number }> = [];
  let existingIndex = -1;

  for (let index = 0; index < current.length; index += 1) {
    const currentReceipt = current[index];
    if (receiptKey(currentReceipt) === key) {
      existingIndex = index;
      continue;
    }
    entries.push({ receipt: currentReceipt, originalIndex: index });
  }

  const lamport = receipt.lamport_clock ?? 0;
  let insertAt = entries.length;
  for (let index = 0; index < entries.length; index += 1) {
    const entryLamport = entries[index].receipt.lamport_clock ?? 0;
    if (entryLamport < lamport || (entryLamport === lamport && existingIndex !== -1 && entries[index].originalIndex > existingIndex)) {
      insertAt = index;
      break;
    }
  }

  const merged = entries.map((entry) => entry.receipt);
  merged.splice(insertAt, 0, receipt);
  return merged.slice(0, 200);
}

function loadingSnapshot(config: AdminSurfaceConfig): CapabilitySnapshot {
  return {
    config,
    data: null,
    records: [],
    readState: { status: "loading", source: config.source, message: "Loading live API state." },
  };
}

async function loadCapabilitySnapshot(config: AdminSurfaceConfig): Promise<CapabilitySnapshot> {
  try {
    const data = await config.read();
    const records = config.rows(data).filter(isRecord) as readonly AdminRecord[];
    return {
      config,
      data,
      records,
      readState: {
        status: records.length > 0 ? "ready" : "empty",
        source: config.source,
        count: records.length,
        message: records.length > 0 ? undefined : config.emptyBody,
      },
    };
  } catch (err) {
    const unauthorized = isUnauthorizedError(err);
    return {
      config,
      data: null,
      records: [],
      readState: {
        status: unauthorized ? "unauthorized" : "unavailable",
        source: config.source,
        message: err instanceof Error ? err.message : "API unavailable",
      },
    };
  }
}

export function useConsoleData(authRevision: number) {
  const [bootstrap, setBootstrap] = useState<ConsoleBootstrap | null>(null);
  const [receipts, setReceipts] = useState<readonly Receipt[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [streamState, setStreamState] = useState<ReceiptStreamState>("connecting");
  const [accessState, setAccessState] = useState<ConsoleAccessState>("unknown");
  const [refreshing, setRefreshing] = useState(false);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    setError(null);
    try {
      const [boot, receiptRows] = await Promise.all([loadBootstrap(), loadReceipts(100)]);
      setBootstrap(boot);
      setReceipts(mergeReceipts(boot.receipts, receiptRows));
      setAccessState("authorized");
      setStreamState("live");
    } catch (err) {
      if (isUnauthorizedError(err)) {
        setAccessState("unauthorized");
        setError("Protected Console APIs require HELM_ADMIN_API_KEY and a matching session key.");
        setStreamState("unauthorized");
      } else {
        setAccessState("unknown");
        setError(err instanceof Error ? err.message : "Console data failed to load");
        setStreamState("disconnected");
      }
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [authRevision, refresh]);

  useEffect(() => {
    const stop = watchReceipts(
      (receipt) => {
        setStreamState("live");
        setReceipts((current) => mergeReceipts(current, [receipt]));
      },
      (err) => {
        if (isUnauthorizedError(err)) {
          setAccessState("unauthorized");
          setError("Receipt streaming requires a valid Console session key.");
          setStreamState("unauthorized");
          return;
        }
        setError(err.message);
        setStreamState("disconnected");
      },
    );
    return stop;
  }, [authRevision]);

  return { bootstrap, receipts, error, streamState, accessState, refreshing, refresh, setReceipts };
}

export function useCapabilitiesData(authRevision: number, enabled = true) {
  const [configs, setConfigs] = useState<readonly AdminSurfaceConfig[]>(DEFAULT_SURFACE_CONFIGS);
  const [snapshots, setSnapshots] = useState<readonly CapabilitySnapshot[]>(() => DEFAULT_SURFACE_CONFIGS.map(loadingSnapshot));
  const [loading, setLoading] = useState(true);

  const refreshOne = useCallback(async (id: string) => {
    if (!enabled) return;
    const config = ADMIN_SURFACES[id];
    if (!config) return;
    setSnapshots((current) => current.map((snapshot) => (snapshot.config.id === id ? loadingSnapshot(config) : snapshot)));
    const next = await loadCapabilitySnapshot(config);
    setSnapshots((current) => current.map((snapshot) => (snapshot.config.id === id ? next : snapshot)));
  }, [enabled]);

  const refreshAll = useCallback(async () => {
    if (!enabled) return;
    setLoading(true);
    setSnapshots(configs.map(loadingSnapshot));
    const next = await Promise.all(configs.map(loadCapabilitySnapshot));
    setSnapshots(next);
    setLoading(false);
  }, [configs, enabled]);

  useEffect(() => {
    if (!enabled) {
      setConfigs(DEFAULT_SURFACE_CONFIGS);
      setSnapshots([]);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setSnapshots(DEFAULT_SURFACE_CONFIGS.map(loadingSnapshot));
    void (async () => {
      let nextConfigs: readonly AdminSurfaceConfig[];
      try {
        const catalog = await loadConsoleSurfaceCatalog();
        nextConfigs = configsFromCatalog(catalog.surfaces.map((surface) => surface.id));
      } catch {
        nextConfigs = DEFAULT_SURFACE_CONFIGS;
      }
      const next = await Promise.all(nextConfigs.map(loadCapabilitySnapshot));
      if (cancelled) return;
      setConfigs(nextConfigs);
      setSnapshots(next);
      setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [authRevision, enabled]);

  return { capabilities: buildCapabilities(snapshots), snapshots, loading, refreshOne, refreshAll };
}
