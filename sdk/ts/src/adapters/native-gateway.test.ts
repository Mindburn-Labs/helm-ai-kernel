import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fromOpenAIAgentsToolCall } from "./agent-frameworks.js";
import {
  NATIVE_GATEWAY_PROTOCOL_VERSION,
  NativeGatewayClient,
  type NativeGatewayConfig,
  NativeGatewayError,
} from "./native-gateway.js";

// Independent HTTP fixtures from mcpserver http.go/gateway.go. These establish
// client wire/outcome handling, not provider execution or authority enforcement.
const attemptId = "11111111-1111-7111-8111-111111111111";
const otherAttemptId = "22222222-2222-7222-8222-222222222222";
const target = "github:owner/repository";
const toolName = "github_pull_request_create";
const effect = {
  toolName,
  target,
  arguments: { title: "Review me", head: "work", base: "main" },
};
type Request = { id: string; method: string; params: Record<string, unknown> };
type Handler = (
  req: IncomingMessage,
  body: Request,
  res: ServerResponse,
) => void;

function nativeResult(
  res: ServerResponse,
  id: string,
  result: Record<string, unknown>,
) {
  res.setHeader("Content-Type", "application/json");
  res.end(
    JSON.stringify({
      jsonrpc: "2.0",
      id,
      result: {
        ...result,
        resultType: "complete",
        _meta: {
          "io.modelcontextprotocol/serverInfo": {
            name: "helm-gateway",
            version: "fixture",
          },
        },
      },
    }),
  );
}

function outcome(
  state = "OBSERVED",
  status = "succeeded",
  extra: Record<string, unknown> = {},
) {
  return {
    attempt_id: attemptId,
    effect_type: "github.pull_request.create",
    target,
    state,
    status,
    ...(status === "succeeded"
      ? {
          outcome: "SUCCEEDED",
          result_kind: "github_pull_request",
          result: { number: 37 },
        }
      : {}),
    ...extra,
  };
}

function toolResponse(
  res: ServerResponse,
  id: string,
  value: Record<string, unknown>,
  isError = false,
) {
  nativeResult(res, id, {
    structuredContent: value,
    isError,
    content: [{ type: "text", text: JSON.stringify(value) }],
  });
}

describe("native gateway framework client", () => {
  let server: Server;
  let url: string;
  let handler: Handler;
  let requests: {
    headers: IncomingMessage["headers"];
    url: string | undefined;
    body: Request;
  }[];

  beforeEach(async () => {
    requests = [];
    handler = (_req, body, res) => toolResponse(res, body.id, outcome());
    server = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(Buffer.from(chunk));
      const body = JSON.parse(Buffer.concat(chunks).toString()) as Request;
      requests.push({ headers: req.headers, url: req.url, body });
      handler(req, body, res);
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("fixture has no port");
    url = `http://127.0.0.1:${address.port}/mcp`;
  });

  afterEach(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  });

  function client(config: Partial<NativeGatewayConfig> = {}) {
    return new NativeGatewayClient({
      mcpUrl: url,
      episodeToken: () => "fixture-a",
      ...config,
    });
  }

  it("sends exact normalized framework arguments to the native effect interface", async () => {
    const normalized = fromOpenAIAgentsToolCall({
      id: "vendor-call",
      name: toolName,
      arguments: JSON.stringify({
        title: "Review me",
        head: "work",
        base: "main",
        nested: { flag: true, items: [1, null] },
      }),
      metadata: { tenant_id: "untrusted-metadata" },
    });
    const result = await client().callEffect({ ...normalized, target });
    expect(result.structuredContent).toMatchObject({
      attempt_id: attemptId,
      status: "succeeded",
      outcome: "SUCCEEDED",
      result: { number: 37 },
    });
    expect(requests).toHaveLength(1);
    expect(requests[0].url).toBe("/mcp");
    expect(requests[0].headers).toMatchObject({
      authorization: "Bearer fixture-a",
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "mcp-protocol-version": "2026-07-28",
      "mcp-method": "tools/call",
      "mcp-name": toolName,
    });
    expect(requests[0].headers["x-api-key"]).toBeUndefined();
    expect(requests[0].body).toEqual({
      jsonrpc: "2.0",
      id: expect.any(String),
      method: "tools/call",
      params: {
        name: toolName,
        arguments: { target, arguments: normalized.arguments },
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    });
    expect(NATIVE_GATEWAY_PROTOCOL_VERSION).toBe("2026-07-28");
  });

  it("reads fresh credential-scoped definitions without granting authority or caching", async () => {
    let token = "first-seat";
    handler = (req, body, res) => {
      const tools =
        req.headers.authorization === "Bearer first-seat"
          ? [
              {
                name: toolName,
                inputSchema: {
                  type: "object",
                  additionalProperties: false,
                  required: ["target", "arguments"],
                  properties: {
                    target: { type: "string" },
                    arguments: { type: "object" },
                  },
                },
              },
            ]
          : [];
      nativeResult(res, body.id, {
        tools,
        ttlMs: 60000,
        cacheScope: "private",
      });
    };
    const native = client({ episodeToken: () => token });
    expect(await native.listTools()).toMatchObject([
      { name: toolName, inputSchema: { required: ["target", "arguments"] } },
    ]);
    token = "other-seat";
    expect(await native.listTools()).toEqual([]);
    expect(requests.map((r) => r.body.method)).toEqual([
      "tools/list",
      "tools/list",
    ]);
    expect(requests.every((r) => r.headers["mcp-name"] === undefined)).toBe(
      true,
    );
  });

  it.each([
    ["ESCALATED", "escalated", false],
    ["UNKNOWN", "reconciling", false],
    ["DISPATCHING", "reconciling", false],
    ["DISPATCHED", "reconciling", false],
    ["DENIED", "denied", true],
    ["REJECTED", "rejected", true],
    ["EXPIRED", "expired", true],
    ["CANCELLED", "cancelled", true],
    ["RECONCILED", "failed", true],
  ])("preserves native %s/%s without treating transport completion as acceptance", async (state, status, isError) => {
    handler = (_req, body, res) =>
      toolResponse(
        res,
        body.id,
        outcome(state, status, {
          reason_code: "FIXTURE_REASON",
          outcome: "UNKNOWN",
        }),
        isError,
      );
    expect(await client().callEffect(effect)).toMatchObject({
      isError,
      structuredContent: {
        state,
        status,
        reason_code: "FIXTURE_REASON",
        attempt_id: attemptId,
      },
    });
    expect(requests).toHaveLength(1);
  });

  it.each([
    "invalid",
    "denied",
    "not_found",
    "conflict",
    "refused",
  ])("keeps %s refusals without inventing an attempt", async (status) => {
    handler = (_req, body, res) =>
      toolResponse(
        res,
        body.id,
        {
          status,
          reason_code: "EFFECT_OUT_OF_SCOPE",
          message: "fixture refusal",
        },
        true,
      );
    expect(await client().callEffect(effect)).toEqual({
      isError: true,
      structuredContent: {
        status,
        reason_code: "EFFECT_OUT_OF_SCOPE",
        message: "fixture refusal",
      },
    });
  });

  it("reattaches through getAttempt using fresh credentials and the original attempt", async () => {
    handler = (_req, body, res) =>
      toolResponse(res, body.id, outcome("UNKNOWN", "reconciling"));
    const original = await client().callEffect(effect);
    handler = (_req, body, res) => toolResponse(res, body.id, outcome());
    const successor = client({ episodeToken: () => "fixture-b" });
    expect(
      await successor.getAttempt(
        original.structuredContent.attempt_id as string,
      ),
    ).toMatchObject({
      structuredContent: { attempt_id: attemptId, status: "succeeded" },
    });
    expect(requests[1].body.params.arguments).toEqual({
      attempt_id: attemptId,
    });
    expect(requests[1].headers.authorization).toBe("Bearer fixture-b");
    expect(
      requests.filter((r) => r.body.params.name === toolName),
    ).toHaveLength(1);
  });

  it("preserves not_found when a successor lacks continuation authority", async () => {
    handler = (_req, body, res) =>
      toolResponse(
        res,
        body.id,
        { status: "not_found", reason_code: "NOT_FOUND" },
        true,
      );
    expect(await client().getAttempt(attemptId)).toEqual({
      isError: true,
      structuredContent: { status: "not_found", reason_code: "NOT_FOUND" },
    });
  });

  it.each([
    ["dispatch", "refused", "PERMIT_EXPIRED"],
    ["observation", "denied", "INSUFFICIENT_PRIVILEGE"],
  ])("retains a minimal %s refusal's attempt ID for read-back without another write", async (_phase, status, reason) => {
    // Exact gateway.go refusal(err, id) shape from the Dispatch/Observe paths:
    // no state/effect_type/target, but a known attempt that must not be lost.
    const refusal = {
      status,
      reason_code: reason,
      message: "fixture refusal",
      attempt_id: attemptId,
    };
    handler = (_req, body, res) => toolResponse(res, body.id, refusal, true);
    const native = client();
    const result = await native.callEffect(effect);
    expect(result).toEqual({ isError: true, structuredContent: refusal });
    handler = (_req, body, res) =>
      toolResponse(res, body.id, outcome("UNKNOWN", "reconciling"));
    expect(
      await native.getAttempt(result.structuredContent.attempt_id as string),
    ).toMatchObject({
      structuredContent: {
        attempt_id: attemptId,
        state: "UNKNOWN",
        status: "reconciling",
      },
    });
    expect(requests[1].body.params.arguments).toEqual({
      attempt_id: attemptId,
    });
    expect(
      requests.filter((request) => request.body.params.name === toolName),
    ).toHaveLength(1);
  });

  it("never repeats an effect when its response is lost after dispatch", async () => {
    let dispatches = 0;
    handler = (_req, _body, res) => {
      dispatches++;
      res.destroy();
    };
    await expect(client().callEffect(effect)).rejects.toMatchObject({
      name: "NativeGatewayError",
      kind: "transport",
      effectMayHaveOccurred: true,
      requestId: expect.any(String),
    });
    expect(dispatches).toBe(1);
    expect(requests).toHaveLength(1);
  });

  it("does not infer an unsent effect from cancellation after the server received it", async () => {
    const controller = new AbortController();
    handler = () => controller.abort();
    await expect(
      client().callEffect(effect, { signal: controller.signal }),
    ).rejects.toMatchObject({ effectMayHaveOccurred: true });
    handler = (_req, body, res) =>
      toolResponse(res, body.id, outcome("UNKNOWN", "reconciling"));
    expect(await client().getAttempt(attemptId)).toMatchObject({
      structuredContent: { state: "UNKNOWN", status: "reconciling" },
    });
    expect(
      requests.filter((r) => r.body.params.name === toolName),
    ).toHaveLength(1);
  });

  it("does not send an effect when cancelled before the request", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      client().callEffect(effect, { signal: controller.signal }),
    ).rejects.toMatchObject({ effectMayHaveOccurred: false });
    expect(requests).toHaveLength(0);
  });

  it("bounds waiting without retrying or declaring the effect stopped", async () => {
    handler = () => {};
    await expect(
      client({ timeoutMs: 30 }).callEffect(effect),
    ).rejects.toMatchObject({ effectMayHaveOccurred: true });
    expect(requests).toHaveLength(1);
  });

  it("bounds token lookup before a request can be sent", async () => {
    await expect(
      client({
        timeoutMs: 20,
        episodeToken: () => new Promise(() => {}),
      }).callEffect(effect),
    ).rejects.toMatchObject({
      kind: "transport",
      effectMayHaveOccurred: false,
    });
    expect(requests).toHaveLength(0);
  });

  it("does not treat a discovered tool as continuing authority after revocation", async () => {
    handler = (_req, body, res) =>
      nativeResult(res, body.id, {
        tools: [{ name: toolName, inputSchema: { type: "object" } }],
        ttlMs: 60000,
        cacheScope: "private",
      });
    const native = client();
    await native.listTools();
    handler = (_req, body, res) =>
      toolResponse(
        res,
        body.id,
        { status: "denied", reason_code: "MANDATE_INACTIVE" },
        true,
      );
    expect(await native.callEffect(effect)).toMatchObject({
      isError: true,
      structuredContent: { status: "denied", reason_code: "MANDATE_INACTIVE" },
    });
    expect(requests).toHaveLength(2);
  });

  it.each([
    401, 403, 429, 503,
  ])("returns HTTP %s separately from native outcomes without retries", async (status) => {
    handler = (_req, _body, res) => {
      res.writeHead(status);
      res.end("not a tool result");
    };
    await expect(client().callEffect(effect)).rejects.toMatchObject({
      kind: "http",
      code: status,
    });
    expect(requests).toHaveLength(1);
  });

  it.each([
    -32022, -32603,
  ])("refuses RPC failure %s without the suggested automatic replay", async (code) => {
    handler = (_req, body, res) => {
      res.setHeader("Content-Type", "application/json");
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: body.id,
          error: { code, message: "repeat it" },
        }),
      );
    };
    await expect(client().callEffect(effect)).rejects.toMatchObject({
      kind: "rpc",
      code,
      effectMayHaveOccurred: true,
    });
    expect(requests).toHaveLength(1);
  });

  it.each([
    ["mismatched target", { ...outcome(), target: "github:other/private" }],
    [
      "mismatched effect",
      { ...outcome(), effect_type: "github.repository.get" },
    ],
    ["missing attempt", { status: "succeeded", outcome: "SUCCEEDED" }],
    ["unknown state called success", outcome("UNKNOWN")],
    [
      "unconfirmed success",
      outcome("OBSERVED", "succeeded", { outcome: "UNKNOWN" }),
    ],
    ["new unsupported status", { ...outcome(), status: "accepted" }],
    ["malformed attempt", { ...outcome(), attempt_id: "not-a-uuid" }],
    ["denial called escalation", outcome("DENIED", "escalated")],
  ])("rejects %s as an uncertain response", async (_name, value) => {
    handler = (_req, body, res) => toolResponse(res, body.id, value);
    await expect(client().callEffect(effect)).rejects.toMatchObject({
      kind: "protocol",
      effectMayHaveOccurred: true,
    });
    expect(requests).toHaveLength(1);
  });

  it("rejects an attempt response with a substituted identity", async () => {
    handler = (_req, body, res) =>
      toolResponse(res, body.id, { ...outcome(), attempt_id: otherAttemptId });
    await expect(client().getAttempt(attemptId)).rejects.toMatchObject({
      kind: "protocol",
      effectMayHaveOccurred: false,
    });
  });

  it.each([
    "partial",
    "task-handle",
    "wrong-id",
    "missing-structured",
    "error-and-result",
    "wrong-error-flag",
    "truncated",
    "event-stream",
  ])("rejects unsupported or malformed %s responses", async (mode) => {
    handler = (_req, body, res) => {
      const result: Record<string, unknown> = {
        resultType: "complete",
        _meta: {
          "io.modelcontextprotocol/serverInfo": {
            name: "helm-gateway",
            version: "fixture",
          },
        },
        isError: false,
        structuredContent: outcome(),
      };
      if (mode === "partial") result.resultType = "partial";
      if (mode === "task-handle") {
        result.resultType = "task";
        result.task = { taskId: "remote" };
      }
      if (mode === "missing-structured") delete result.structuredContent;
      if (mode === "wrong-error-flag") result.isError = true;
      res.setHeader(
        "Content-Type",
        mode === "event-stream" ? "text/event-stream" : "application/json",
      );
      res.end(
        mode === "truncated"
          ? '{"jsonrpc":"2.0"'
          : JSON.stringify({
              jsonrpc: "2.0",
              id: mode === "wrong-id" ? "other" : body.id,
              result,
              ...(mode === "error-and-result"
                ? { error: { code: -32603, message: "ambiguous" } }
                : {}),
            }),
      );
    };
    await expect(client().callEffect(effect)).rejects.toMatchObject({
      kind: "protocol",
      effectMayHaveOccurred: true,
    });
  });

  it("rejects stale pagination or malformed discovery instead of dropping definitions", async () => {
    handler = (_req, body, res) =>
      nativeResult(res, body.id, {
        tools: [],
        ttlMs: 60000,
        cacheScope: "private",
        nextCursor: "unsupported",
      });
    await expect(client().listTools()).rejects.toMatchObject({
      kind: "protocol",
      effectMayHaveOccurred: false,
    });
  });

  it("snapshots exact material arguments before asynchronous token lookup", async () => {
    let provideToken: (token: string) => void = () => {};
    const pendingToken = new Promise<string>((resolve) => {
      provideToken = resolve;
    });
    const mutable = { ...effect, arguments: { title: "approved revision" } };
    const pending = client({ episodeToken: () => pendingToken }).callEffect(
      mutable,
    );
    mutable.arguments.title = "changed after call";
    mutable.target = "changed-target";
    provideToken("fixture-a");
    await pending;
    expect(requests[0].body.params.arguments).toEqual({
      target,
      arguments: { title: "approved revision" },
    });
  });

  it.each([
    undefined,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    () => {},
    new Date(),
    1n,
  ])("rejects non-JSON material values before dispatch: %s", (value) => {
    expect(() =>
      client().callEffect({ ...effect, arguments: { value } }),
    ).toThrow(TypeError);
    expect(requests).toHaveLength(0);
  });

  it("rejects implicit effect name normalization, reserved reads and oversized requests", () => {
    expect(() =>
      client().callEffect({
        ...effect,
        toolName: "github.pull_request.create",
      }),
    ).toThrow(TypeError);
    expect(() =>
      client().callEffect({ ...effect, toolName: "helm_attempt_get" }),
    ).toThrow(TypeError);
    expect(() => client().getAttempt("not-an-attempt")).toThrow(TypeError);
    return expect(
      client().callEffect({
        ...effect,
        arguments: { text: "x".repeat(256 * 1024) },
      }),
    ).rejects.toThrow(TypeError);
  });

  it("refuses JSON transformations that would silently change material input", () => {
    const sparse = Object.assign(new Array<unknown>(1), {
      extra: "replaces missing index",
    });
    const accessor = Object.defineProperty({}, "title", {
      enumerable: true,
      get: () => "changed",
    });
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    for (const value of [
      sparse,
      accessor,
      cycle,
      { [Symbol("hidden")]: true },
    ]) {
      expect(() =>
        client().callEffect({ ...effect, arguments: { value } }),
      ).toThrow(TypeError);
    }
    expect(requests).toHaveLength(0);
  });

  it("bounds partial response bytes and does not mistake them for a result", async () => {
    handler = (_req, _body, res) => {
      res.setHeader("Content-Type", "application/json");
      res.write(" ".repeat(1025));
    };
    await expect(
      client({ maxResponseBytes: 1024 }).callEffect(effect),
    ).rejects.toMatchObject({ kind: "protocol", effectMayHaveOccurred: true });
  });

  it("refuses redirects instead of forwarding credentials or dispatching twice", async () => {
    handler = (_req, _body, res) => {
      res.writeHead(307, { Location: `${url}/alternate` });
      res.end();
    };
    await expect(client().callEffect(effect)).rejects.toMatchObject({
      effectMayHaveOccurred: true,
    });
    expect(requests).toHaveLength(1);
  });

  it("rejects unsafe endpoints and invalid bounds without exposing a token", () => {
    for (const mcpUrl of [
      "http://remote.example/mcp",
      "https://user:pwd@remote.example/mcp",
      `${url}?credential=example`,
      `${url}#fragment`,
    ]) {
      expect(() => client({ mcpUrl })).toThrow(TypeError);
    }
    expect(() => client({ timeoutMs: 0 })).toThrow(TypeError);
    expect(() =>
      client({ maxResponseBytes: Number.POSITIVE_INFINITY }),
    ).toThrow(TypeError);
    expect(
      new NativeGatewayError("transport", "id", true).message,
    ).not.toContain("fixture-a");
  });
});
