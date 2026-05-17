import { describe, expect, it } from "vitest";
import { appendSseChunk, createSseFrameBuffer } from "./sse";

describe("SSE frame buffer", () => {
  it("emits complete LF-delimited frames across chunks", () => {
    const state = createSseFrameBuffer();
    const frames: string[] = [];

    appendSseChunk(state, "event: one\ndata: {", (frame) => frames.push(frame));
    appendSseChunk(state, "\"type\":\"one\"}\n\nevent: two\n", (frame) => frames.push(frame));

    expect(frames).toEqual(["event: one\ndata: {\"type\":\"one\"}"]);
    expect(state.buffer).toBe("event: two\n");
  });

  it("handles CRLF delimiters split across chunk boundaries", () => {
    const state = createSseFrameBuffer();
    const frames: string[] = [];

    appendSseChunk(state, "event: receipt\r\ndata: {}\r", (frame) => frames.push(frame));
    appendSseChunk(state, "\n\r\n", (frame) => frames.push(frame));

    expect(frames).toEqual(["event: receipt\r\ndata: {}"]);
    expect(state.buffer).toBe("");
  });
});
