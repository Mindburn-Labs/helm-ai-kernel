export interface SseFrameBuffer {
  buffer: string;
  scanFrom: number;
}

export function createSseFrameBuffer(): SseFrameBuffer {
  return { buffer: "", scanFrom: 0 };
}

export function appendSseChunk(state: SseFrameBuffer, chunk: string, onFrame: (frame: string) => void): void {
  if (chunk === "") return;
  state.buffer += chunk;

  for (;;) {
    const delimiter = findNextDelimiter(state.buffer, state.scanFrom);
    if (!delimiter) {
      state.scanFrom = Math.max(0, state.buffer.length - 3);
      return;
    }

    onFrame(state.buffer.slice(0, delimiter.index));
    state.buffer = state.buffer.slice(delimiter.index + delimiter.length);
    state.scanFrom = 0;
  }
}

function findNextDelimiter(buffer: string, scanFrom: number): { index: number; length: number } | null {
  const lfIndex = buffer.indexOf("\n\n", scanFrom);
  const crlfIndex = buffer.indexOf("\r\n\r\n", scanFrom);

  if (lfIndex === -1 && crlfIndex === -1) return null;
  if (lfIndex === -1) return { index: crlfIndex, length: 4 };
  if (crlfIndex === -1 || lfIndex < crlfIndex) return { index: lfIndex, length: 2 };
  return { index: crlfIndex, length: 4 };
}
