export type StudioSocketHandler = (event: MessageEvent) => void;

export interface StudioSocketOptions {
  readonly reconnect?: boolean;
  readonly maxRetries?: number;
  readonly backoffBaseMs?: number;
  readonly backoffMaxMs?: number;
}

export interface StudioSocket {
  subscribe(handler: StudioSocketHandler): () => void;
  send(data: string | ArrayBufferLike | Blob | ArrayBufferView): void;
  disconnect(): void;
}

export function connect(url: string, options: StudioSocketOptions = {}): StudioSocket {
  const reconnect = options.reconnect ?? true;
  const maxRetries = options.maxRetries ?? 10;
  const backoffBaseMs = options.backoffBaseMs ?? 500;
  const backoffMaxMs = options.backoffMaxMs ?? 30_000;

  const handlers = new Set<StudioSocketHandler>();
  let socket: WebSocket | null = null;
  let retries = 0;
  let cancelled = false;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  function open(): void {
    if (cancelled) return;
    const next = new WebSocket(url);
    socket = next;

    next.addEventListener("open", () => {
      retries = 0;
    });

    next.addEventListener("message", (event) => {
      handlers.forEach((handler) => handler(event));
    });

    next.addEventListener("close", () => {
      if (cancelled || !reconnect || retries >= maxRetries) return;
      const delay = Math.min(backoffBaseMs * 2 ** retries, backoffMaxMs);
      retries += 1;
      reconnectTimer = setTimeout(open, delay);
    });
  }

  open();

  return {
    subscribe(handler) {
      handlers.add(handler);
      return () => {
        handlers.delete(handler);
      };
    },
    send(data) {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(data);
      }
    },
    disconnect() {
      cancelled = true;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      if (socket) {
        socket.close();
        socket = null;
      }
      handlers.clear();
    },
  };
}
