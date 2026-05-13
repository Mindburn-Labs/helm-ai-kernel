import { useEffect, useMemo, useRef, useState } from "react";
import { Bot, Loader2, MessageSquareMore, X } from "lucide-react";
import { Badge, Button, EmptyState } from "@mindburn/ui-core";
import { useHelmAiKernelAgentProvider } from "./provider";
import { useAiKernelAgentRenderers } from "./renderers";
import { runAiKernelAgent, type AiKernelAgentMessage } from "./runtime";
import type { HelmAiKernelAgentState, AiKernelAgentToolResult } from "./state";
import { useAiKernelFrontendTools } from "./tools";

export function HelmAiKernelAssistantDrawer({
  state,
  open,
  onOpenChange,
  onNavigate,
  onSelectReceipt,
  onSearchChange,
  onDemoActionChange,
}: {
  readonly state: HelmAiKernelAgentState;
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly onNavigate: (surface: string) => void;
  readonly onSelectReceipt: (receiptId: string) => void;
  readonly onSearchChange: (query: string) => void;
  readonly onDemoActionChange: (action: string) => void;
}) {
  const { runtimeUrl } = useHelmAiKernelAgentProvider();
  const [threadId] = useState(() => `helm-ai-kernel-${Date.now()}`);
  const [draft, setDraft] = useState("Explain the selected DENY receipt and show the safest proof demo step.");
  const [messages, setMessages] = useState<AiKernelAgentMessage[]>([]);
  const [streaming, setStreaming] = useState<AiKernelAgentMessage | null>(null);
  const [results, setResults] = useState<AiKernelAgentToolResult[]>([]);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const frontendToolHandlers = useMemo(
    () => ({
      navigateSurface: onNavigate,
      selectReceipt: onSelectReceipt,
      setSearchQuery: onSearchChange,
      chooseDemoAction: onDemoActionChange,
    }),
    [onDemoActionChange, onNavigate, onSearchChange, onSelectReceipt],
  );
  useAiKernelAgentRenderers();
  useAiKernelFrontendTools(frontendToolHandlers);

  useEffect(() => () => abortRef.current?.abort(), []);

  const submit = async () => {
    const prompt = draft.trim();
    if (!prompt || running) return;
    const controller = new AbortController();
    abortRef.current?.abort();
    abortRef.current = controller;
    const userMessage: AiKernelAgentMessage = {
      id: `kernel-user-${Date.now()}`,
      role: "user",
      content: prompt,
      createdAt: new Date().toISOString(),
    };
    const assistantMessage: AiKernelAgentMessage = {
      id: `kernel-assistant-${Date.now()}`,
      role: "assistant",
      content: "",
      createdAt: new Date().toISOString(),
    };
    const nextMessages = [...messages, userMessage];
    let assistantContent = "";
    setMessages(nextMessages);
    setStreaming(assistantMessage);
    setResults([]);
    setDraft("");
    setRunning(true);
    setError(null);
    try {
      await runAiKernelAgent({
        runtimeUrl,
        threadId,
        runId: `kernel-run-${Date.now()}`,
        messages: nextMessages,
        state,
        signal: controller.signal,
        onEvent: (event) => {
          if (event.type === "TEXT_MESSAGE_CONTENT") {
            const delta = typeof event.delta === "string" ? event.delta : "";
            assistantContent += delta;
            setStreaming((current) => (current ? { ...current, content: current.content + delta } : current));
          }
          if (event.type === "TOOL_CALL_RESULT" && typeof event.content === "string") {
            setResults((current) => [...current, parseResult(event.content as string)]);
          }
        },
      });
      if (assistantContent) {
        setMessages((current) => [...current, { ...assistantMessage, content: assistantContent }]);
      }
    } catch (err) {
      if (!controller.signal.aborted) {
        setError(err instanceof Error ? err.message : "HELM AI Kernel agent run failed");
      }
    } finally {
      setRunning(false);
      setStreaming(null);
    }
  };

  const visibleMessages = streaming ? [...messages, streaming] : messages;

  return (
    <>
      <Button
        aria-label="Open HELM AI Kernel assistant"
        variant="proof"
        size="sm"
        onClick={() => onOpenChange(true)}
        leading={<Bot size={15} aria-hidden="true" />}
      >
        Agent
      </Button>
      {open ? (
        <aside className="assistant-drawer" aria-label="HELM AI Kernel assistant">
          <header>
            <div>
              <Badge label="read-only" tone="proof" />
              <h2>HELM AI Kernel Agent</h2>
            </div>
            <button type="button" className="icon-button" aria-label="Close assistant" onClick={() => onOpenChange(false)}>
              <X size={16} aria-hidden="true" />
            </button>
          </header>
          <div className="assistant-thread" aria-live="polite">
            {visibleMessages.length ? (
              visibleMessages.map((message) => (
                <article key={message.id} className={`assistant-message role-${message.role}`}>
                  <strong>{message.role === "assistant" ? "HELM" : "Operator"}</strong>
                  <p>{message.content || "Streaming..."}</p>
                </article>
              ))
            ) : (
              <EmptyState title="No agent run" body="Ask for receipt explanation, verification, tamper, or replay guidance." />
            )}
            {results.map((result, index) => (
              <article key={`${result.summary}-${index}`} className="agent-result-card">
                <Badge label={result.status} tone="proof" />
                <p>{result.summary}</p>
              </article>
            ))}
          </div>
          <form
            className="assistant-composer"
            onSubmit={(event) => {
              event.preventDefault();
              void submit();
            }}
          >
            <textarea value={draft} rows={3} onChange={(event) => setDraft(event.target.value)} />
            <div>
              <Button
                type="submit"
                variant="primary"
                disabled={running || draft.trim() === ""}
                leading={running ? <Loader2 className="spin" size={15} aria-hidden="true" /> : <MessageSquareMore size={15} aria-hidden="true" />}
              >
                Run
              </Button>
            </div>
            {error ? <p className="assistant-error">{error}</p> : null}
          </form>
        </aside>
      ) : null}
    </>
  );
}

function parseResult(content: string): AiKernelAgentToolResult {
  try {
    return JSON.parse(content) as AiKernelAgentToolResult;
  } catch {
    return { status: "complete", summary: content };
  }
}
