import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HelmClient } from "./client.js";
import type { DecisionRequest } from "./types.gen.js";

function jsonResponse(
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json", ...headers },
  });
}

describe("evaluateDecisionWithScope", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("binds authenticated scope and sends only the canonical request body", async () => {
    fetchSpy.mockResolvedValue(
      jsonResponse(
        { id: "decision-1", tenant_id: "tenant-a", session_id: "session-a" },
        {
          "X-Helm-Receipt-ID": "rcpt-decision-1",
          "X-Helm-Idempotency-Replayed": "true",
        },
      ),
    );
    const client = new HelmClient({
      baseUrl: "http://helm.test",
      apiKey: "token",
      tenantId: "tenant-default",
      principalId: "principal-default",
      workspaceId: "workspace-default",
    });
    const request = {
      action: "read_ticket",
      resource: "ticket:1",
      context: { priority: "low" },
      session_history: [{
        action: "read_history",
        resource: "ticket:0",
        verdict: "ALLOW",
        timestamp: 1,
        principal: "spoofed-history-principal",
      }],
      principal: "spoofed-principal",
    } as DecisionRequest;

    const result = await client.evaluateDecisionWithScope(
      request,
      {
        tenantId: "tenant-a",
        principalId: "principal-a",
        sessionId: "session-a",
        workspaceId: "workspace-a",
      },
      "request-1",
    );

    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://helm.test/api/v1/evaluate");
    expect(init.headers).toMatchObject({
      Authorization: "Bearer token",
      "X-Helm-Tenant-ID": "tenant-a",
      "X-Helm-Principal-ID": "principal-a",
      "X-Helm-Session-ID": "session-a",
      "X-Helm-Workspace-ID": "workspace-a",
      "Idempotency-Key": "request-1",
    });
    expect(JSON.parse(init.body as string)).toEqual({
      action: "read_ticket",
      resource: "ticket:1",
      context: { priority: "low" },
      session_history: [{
        action: "read_history",
        resource: "ticket:0",
        verdict: "ALLOW",
        timestamp: 1,
      }],
    });
    expect(result.decision.id).toBe("decision-1");
    expect(result.receiptId).toBe("rcpt-decision-1");
    expect(result.replayed).toBe(true);
  });

  it("rejects missing authentication or scope before making a request", async () => {
    const request: DecisionRequest = {
      action: "read_ticket",
      resource: "ticket:1",
    };
    const clientWithoutKey = new HelmClient({ baseUrl: "http://helm.test" });
    await expect(
      clientWithoutKey.evaluateDecisionWithScope(request, {
        tenantId: "tenant-a",
        principalId: "principal-a",
        sessionId: "session-a",
      }),
    ).rejects.toThrow("apiKey is required");

    const client = new HelmClient({
      baseUrl: "http://helm.test",
      apiKey: "token",
    });
    await expect(
      client.evaluateDecisionWithScope(request, {
        tenantId: "tenant-a",
        principalId: "principal-a",
        sessionId: "",
      }),
    ).rejects.toThrow("sessionId is required");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("does not send a configured workspace when the explicit scope omits it", async () => {
    fetchSpy.mockResolvedValue(
      jsonResponse(
        { id: "decision-2", tenant_id: "tenant-a", session_id: "session-a" },
        { "X-Helm-Receipt-ID": "rcpt-decision-2" },
      ),
    );
    const client = new HelmClient({
      baseUrl: "http://helm.test",
      apiKey: "token",
      workspaceId: "workspace-default",
    });

    await client.evaluateDecisionWithScope(
      { action: "read_ticket", resource: "ticket:2" },
      { tenantId: "tenant-a", principalId: "principal-a", sessionId: "session-a" },
    );

    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(init.headers).not.toHaveProperty("X-Helm-Workspace-ID");
  });

  it("rejects a successful evaluator response without its required receipt ID", async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ id: "decision-3" }));
    const client = new HelmClient({ baseUrl: "http://helm.test", apiKey: "token" });

    await expect(
      client.evaluateDecisionWithScope(
        { action: "read_ticket", resource: "ticket:3" },
        { tenantId: "tenant-a", principalId: "principal-a", sessionId: "session-a" },
      ),
    ).rejects.toThrow("missing required X-Helm-Receipt-ID");
  });

  it("rejects the retired generic evaluator without making a request", async () => {
    const client = new HelmClient({ baseUrl: "http://helm.test" });
    await expect(client.evaluateDecision({ principal: "spoofed" })).rejects.toThrow("evaluateDecision is retired");
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
