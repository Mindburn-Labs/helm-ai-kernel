import type { HelmOssAgentState } from "./state";

export interface OssAgentMessage {
  readonly id: string;
  readonly role: "user" | "assistant" | "tool" | "system";
  readonly content: string;
  readonly createdAt: string;
}

export interface OssAgentEvent {
  type: string;
  [key: string]: unknown;
}

export async function runOssAgent(input: {
  readonly runtimeUrl?: string;
  readonly threadId: string;
  readonly runId: string;
  readonly messages: readonly OssAgentMessage[];
  readonly state: HelmOssAgentState;
  readonly onEvent: (event: OssAgentEvent) => void;
  readonly signal?: AbortSignal;
}) {
  const response = await fetch(`${(input.runtimeUrl ?? "/api/v1/agent-ui").replace(/\/$/, "")}/run`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      threadId: input.threadId,
      runId: input.runId,
      workspaceId: input.state.workspace?.project ?? "oss",
      currentSurface: input.state.surface,
      messages: input.messages.map((message) => ({
        id: message.id,
        role: message.role,
        content: message.content,
      })),
      state: input.state,
    }),
    signal: input.signal,
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  if (!response.body) {
    throw new Error("AG-UI runtime returned no stream body.");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const frames = buffer.split("\n\n");
    buffer = frames.pop() ?? "";
    for (const frame of frames) {
      const event = parseSSEFrame(frame);
      if (event) input.onEvent(event);
    }
  }
}

function parseSSEFrame(frame: string): OssAgentEvent | null {
  const lines = frame.split("\n");
  let eventType = "";
  const data: string[] = [];
  for (const line of lines) {
    if (line.startsWith("event:")) eventType = line.slice("event:".length).trim();
    if (line.startsWith("data:")) data.push(line.slice("data:".length).trimStart());
  }
  if (!data.length) return null;
  try {
    const parsed = JSON.parse(data.join("\n")) as OssAgentEvent;
    if (!parsed.type && eventType) parsed.type = eventType;
    return parsed;
  } catch {
    return eventType ? { type: eventType, data: data.join("\n") } : null;
  }
}
