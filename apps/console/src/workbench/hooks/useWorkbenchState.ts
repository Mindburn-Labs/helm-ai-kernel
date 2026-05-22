import { useCallback, useMemo, useRef, useState } from "react";
import {
  MessageSquareText,
  Rocket,
  Play,
  Boxes,
  ShieldCheck,
  KeyRound,
  FileSearch,
  Archive,
  Command as CommandIcon,
  Settings,
} from "lucide-react";
import {
  evaluateIntent,
  loadReceipts,
  replayVerifyCurrentEvidence,
  type ConsoleBootstrap,
  type Receipt,
} from "../../api/client";
import { buildAiKernelAgentState } from "../../agent/state";
import { mergeReceipts, useCapabilitiesData, useConsoleData } from "../dataHooks";
import {
  buildOperatorTasks,
  buildWorkbenchSnapshot,
  parseGovernedCommand,
  receiptAction,
  receiptKey,
  receiptResource,
  routeForCapability,
  shortId,
  normalizeState,
} from "../viewModels";
import type {
  FlowRoute,
  DrawerItem,
  SearchResult,
  GovernedCommand,
  OperatorTask,
  Capability,
  QuickAction,
  CommandSource,
} from "../types";

export const FLOW_NAV = [
  { id: "workbench", label: "Chat Workspace", icon: MessageSquareText },
  { id: "apps", label: "App Hub", icon: Rocket },
  { id: "runs", label: "Runs", icon: Play },
  { id: "mcp", label: "MCP Firewall", icon: Boxes },
  { id: "policies", label: "Policies", icon: ShieldCheck },
  { id: "secrets", label: "Secrets", icon: KeyRound },
  { id: "sandbox", label: "Sandbox", icon: FileSearch },
  { id: "evidence", label: "Evidence", icon: Archive },
  { id: "receipts", label: "Receipts", icon: CommandIcon },
  { id: "registry", label: "Registry", icon: CommandIcon },
  { id: "settings", label: "Settings", icon: Settings },
] as const;

function initialRouteFromLocation(): { route: FlowRoute; runId: string } {
  if (typeof window === "undefined") return { route: "workbench", runId: "" };
  const pathname = window.location.pathname.replace(/\/+$/, "");
  const runMatch = pathname.match(/^\/runs\/([^/]+)$/);
  if (runMatch?.[1]) return { route: "runs", runId: decodeURIComponent(runMatch[1]) };
  const firstSegment = pathname.split("/").filter(Boolean)[0] as FlowRoute | undefined;
  if (firstSegment && FLOW_NAV.some((item) => item.id === firstSegment)) {
    return { route: firstSegment, runId: "" };
  }
  return { route: "workbench", runId: "" };
}

function buildSearchResults(
  query: string,
  tasks: readonly OperatorTask[],
  capabilities: readonly Capability[],
  receipts: readonly Receipt[],
): readonly SearchResult[] {
  const term = query.trim().toLowerCase();
  if (term.length < 2) return [];
  const results: SearchResult[] = [];
  for (const task of tasks) {
    const text = `${task.title} ${task.summary} ${task.source} ${task.state}`.toLowerCase();
    if (text.includes(term)) {
      results.push({ id: `task-${task.id}`, label: task.title, detail: `${task.state} · ${task.source}`, route: task.route, item: { kind: "task", task } });
    }
  }
  for (const capability of capabilities) {
    const text = `${capability.label} ${capability.group} ${capability.sourceEndpoint} ${capability.status}`.toLowerCase();
    if (text.includes(term)) {
      results.push({
        id: `capability-${capability.id}`,
        label: capability.label,
        detail: `${capability.group} · ${capability.sourceEndpoint}`,
        route: routeForCapability(capability.id),
        item: { kind: "capability", capability },
      });
    }
    for (const action of capability.actions) {
      const actionText = `${action.label} ${action.endpoint} ${action.risk}`.toLowerCase();
      if (actionText.includes(term)) {
        results.push({
          id: `action-${action.id}`,
          label: action.label,
          detail: `${capability.label} · ${action.method}`,
          route: routeForCapability(capability.id),
          item: { kind: "action", capability, action },
        });
      }
    }
  }
  for (const receipt of receipts.slice(0, 60)) {
    const text = `${receipt.receipt_id} ${receipt.status} ${receiptAction(receipt)} ${receiptResource(receipt)} ${receipt.executor_id}`.toLowerCase();
    if (text.includes(term)) {
      results.push({
        id: `receipt-${receiptKey(receipt)}`,
        label: shortId(receipt.receipt_id),
        detail: `${receiptAction(receipt)} · ${normalizeState(receipt.status, "pending")}`,
        route: "ledger",
        item: { kind: "receipt", receipt },
      });
    }
  }
  return results.slice(0, 10);
}

export function useWorkbenchState() {
  const initialRoute = useMemo(() => initialRouteFromLocation(), []);
  const [authRevision, setAuthRevision] = useState(0);
  
  const {
    bootstrap,
    receipts,
    error,
    streamState,
    accessState,
    refreshing,
    refresh,
    setReceipts,
  } = useConsoleData(authRevision);

  const [active, setActive] = useState<FlowRoute>(initialRoute.route);
  const [isInspectorCollapsed, setIsInspectorCollapsed] = useState(false);
  const [inspectorTab, setInspectorTab] = useState<"activity" | "boundary" | "mcp" | "runtime" | "evidence" | "raw">("activity");

  const needsCapabilityData =
    active === "developer" ||
    active === "workbench" ||
    active === "work" ||
    active === "ledger" ||
    active === "capabilities" ||
    active === "settings";

  const {
    capabilities,
    loading: capabilitiesLoading,
    refreshOne,
    refreshAll,
  } = useCapabilitiesData(authRevision, needsCapabilityData);

  const [query, setQuery] = useState("");
  const [drawerItem, setDrawerItem] = useState<DrawerItem | null>(null);
  const [commandText, setCommandText] = useState("LLM_INFERENCE gpt-4.1-mini");
  const [principal, setPrincipal] = useState("operator@local");
  const [currentCommand, setCurrentCommand] = useState<GovernedCommand | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [replayStatus, setReplayStatus] = useState("not checked");
  const [assistantOpen, setAssistantOpen] = useState(false);
  const composerRef = useRef<HTMLTextAreaElement | null>(null);

  const authChanged = useCallback(() => {
    setAuthRevision((value) => value + 1);
  }, []);

  const selectedReceipt = useMemo(() => {
    if (drawerItem?.kind === "receipt") return drawerItem.receipt;
    return receipts[0] ?? null;
  }, [drawerItem, receipts]);

  const tasks = useMemo(
    () => buildOperatorTasks({ bootstrap, receipts, capabilities, accessState, error, streamState }),
    [accessState, bootstrap, capabilities, error, receipts, streamState],
  );

  const snapshot = useMemo(
    () =>
      buildWorkbenchSnapshot({
        bootstrap,
        receipts,
        capabilities,
        accessState,
        error,
        streamState,
        command: currentCommand,
        busy: submitting,
        replayStatus,
      }),
    [accessState, bootstrap, capabilities, currentCommand, error, receipts, replayStatus, streamState, submitting],
  );

  const agentState = useMemo(
    () =>
      buildAiKernelAgentState({
        bootstrap,
        active,
        selectedReceipt,
        query,
        receipts,
        demoAction: "sandbox-lab",
        replayStatus,
      }),
    [active, bootstrap, query, receipts, replayStatus, selectedReceipt],
  );

  const filteredReceipts = useMemo(() => {
    const term = query.trim().toLowerCase();
    if (!term) return receipts;
    return receipts.filter((receipt) => {
      const haystack = [
        receipt.receipt_id,
        receipt.decision_id,
        receipt.effect_id,
        receipt.status,
        receipt.executor_id,
        receiptAction(receipt),
        receiptResource(receipt),
        receipt.blob_hash,
        receipt.output_hash,
      ].join(" ").toLowerCase();
      return haystack.includes(term);
    });
  }, [query, receipts]);

  const searchResults = useMemo(
    () => buildSearchResults(query, tasks, capabilities, receipts),
    [capabilities, query, receipts, tasks],
  );

  const navigate = useCallback((route: FlowRoute, item?: DrawerItem) => {
    setActive(route);
    if (item) setDrawerItem(item);
  }, []);

  const runReplayProbe = useCallback(async (receipt: Receipt | null) => {
    setReplayStatus("checking");
    try {
      const payload = await replayVerifyCurrentEvidence(receipt?.executor_id ?? "");
      const replayCheck = payload.checks?.replay ?? payload.checks?.causal_chain;
      setReplayStatus(payload.verdict ?? replayCheck ?? "verified");
    } catch (err) {
      setReplayStatus(err instanceof Error ? err.message : "replay unavailable");
    }
  }, []);

  const submitCommand = useCallback(async (textOverride?: string, source: CommandSource = "composer") => {
    const text = (textOverride ?? commandText).trim();
    if (!text || submitting) return;
    const command = parseGovernedCommand(text, source, principal);
    setCurrentCommand(command);
    setCommandText(text);
    setActionError(null);

    // Keep active route strictly on "workbench" to ensure zero cockpit redirection
    setActive("workbench");

    if (command.mode === "approve") {
      setIsInspectorCollapsed(false);
      setInspectorTab("boundary");
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      return;
    }
    if (command.mode === "verify") {
      setIsInspectorCollapsed(false);
      setInspectorTab("evidence");
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      return;
    }
    if (command.mode === "replay") {
      setIsInspectorCollapsed(false);
      setInspectorTab("evidence");
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      await runReplayProbe(receipts[0] ?? null);
      return;
    }
    if (command.mode === "inspect") {
      setIsInspectorCollapsed(false);
      if (text.includes("sandbox")) {
        setInspectorTab("boundary");
      } else if (text.includes("mcp")) {
        setInspectorTab("mcp");
      } else {
        setInspectorTab("runtime");
      }
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      return;
    }
    if (command.mode === "launch") {
      setIsInspectorCollapsed(false);
      setInspectorTab("activity");
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      return;
    }

    setSubmitting(true);
    try {
      await evaluateIntent({
        principal,
        action: command.parsedAction ?? "LLM_INFERENCE",
        resource: command.parsedResource ?? "unspecified",
        context: {
          source: "console.workbench",
          workspace: bootstrap?.workspace,
          entered_at: new Date().toISOString(),
        },
      });
      const updated = await loadReceipts(100);
      setReceipts((current) => mergeReceipts(current, updated));
      setIsInspectorCollapsed(false);
      setInspectorTab("activity");
      const targetReceipt = updated[0] ?? receipts[0];
      if (targetReceipt) {
        setDrawerItem({ kind: "receipt", receipt: targetReceipt });
      }
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Intent evaluation failed");
    } finally {
      setSubmitting(false);
    }
  }, [bootstrap?.workspace, commandText, principal, receipts, runReplayProbe, setReceipts, submitting]);

  const runQuickAction = useCallback((action: QuickAction) => {
    if (action.id === "evaluate-intent") {
      setActive("workbench");
      setCommandText(action.command);
      composerRef.current?.focus();
      return;
    }
    if (action.id === "scan-mcp") {
      setActive("workbench");
      setIsInspectorCollapsed(false);
      setInspectorTab("mcp");
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      return;
    }
    if (action.id === "inspect-sandbox") {
      setActive("workbench");
      setIsInspectorCollapsed(false);
      setInspectorTab("boundary");
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      return;
    }
    void submitCommand(action.command, "quick_action");
  }, [submitCommand, receipts]);

  const openSearchResult = (result: SearchResult) => {
    setActive(result.route);
    if (result.item) setDrawerItem(result.item);
  };

  const navigateFromAssistant = useCallback((surface: string) => {
    const route = FLOW_NAV.find((item) => item.id === surface)?.id;
    if (route) setActive(route);
  }, []);

  const selectReceiptFromAssistant = useCallback((receiptId: string) => {
    const receipt = receipts.find((item) => item.receipt_id === receiptId || item.decision_id === receiptId);
    if (receipt) {
      setDrawerItem({ kind: "receipt", receipt });
      setActive("workbench");
      setIsInspectorCollapsed(false);
      setInspectorTab("activity");
    }
  }, [receipts]);

  const onNewSession = useCallback(() => {
    setCommandText("");
    setDrawerItem(null);
    setActive("workbench");
  }, []);

  return {
    onNewSession,
    initialRoute,
    authRevision,
    bootstrap,
    receipts,
    error,
    streamState,
    accessState,
    refreshing,
    refresh,
    active,
    setActive,
    isInspectorCollapsed,
    setIsInspectorCollapsed,
    inspectorTab,
    setInspectorTab,
    needsCapabilityData,
    capabilities,
    capabilitiesLoading,
    refreshOne,
    refreshAll,
    query,
    setQuery,
    drawerItem,
    setDrawerItem,
    commandText,
    setCommandText,
    principal,
    setPrincipal,
    currentCommand,
    submitting,
    actionError,
    replayStatus,
    assistantOpen,
    setAssistantOpen,
    composerRef,
    authChanged,
    selectedReceipt,
    tasks,
    snapshot,
    agentState,
    filteredReceipts,
    searchResults,
    navigate,
    runReplayProbe,
    submitCommand,
    runQuickAction,
    openSearchResult,
    navigateFromAssistant,
    selectReceiptFromAssistant,
  };
}
