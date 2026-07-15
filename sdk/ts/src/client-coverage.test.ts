import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HelmApiError, HelmClient } from "./client.js";

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function helmError(status = 500): Response {
  return jsonResponse(
    { error: { message: "denied", type: "policy", code: "DENY", reason_code: "DENY_POLICY_VIOLATION" } },
    status,
  );
}

describe("HelmClient coverage matrix", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;
  let client: HelmClient;

  beforeEach(() => {
    fetchSpy = vi.fn(async () => jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", fetchSpy);
    client = new HelmClient({
      baseUrl: "http://helm.test/",
      apiKey: "token",
      tenantId: "tenant-a",
      principalId: "principal-a",
      sessionId: "session-a",
      workspaceId: "workspace-a",
      timeout: 5_000,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("constructs fallback API errors for non-HELM bodies", () => {
    expect(new HelmApiError(418, {}).message).toBe("HELM API request failed with HTTP 418");
    expect(new HelmApiError(409, { error: null }).reasonCode).toBe("ERROR_INTERNAL");
    expect(new HelmApiError(400, { error: { message: "bad" } }).message).toBe("HELM API request failed with HTTP 400");
    expect(new HelmApiError(401, { error: { reason_code: "DENY" } }).reasonCode).toBe("ERROR_INTERNAL");
  });

  it("exercises every JSON endpoint wrapper", async () => {
    const calls: Array<[string, unknown[]]> = [
      ["runPublicDemo", ["read_ticket", { id: 1 }]],
      ["verifyPublicDemoReceipt", [{ receipt_id: "r1" }, "hash"]],
      ["approveIntent", [{ intent_hash: "h", signature_b64: "sig", public_key_b64: "pk" }]],
      ["listSessions", []],
      ["listSessions", [7, 3]],
      ["getReceipts", ["session/one"]],
      ["getReceipt", ["receipt#one"]],
      ["createEvidenceEnvelopeManifest", [{ manifest_id: "m1", envelope: "dsse", native_evidence_hash: "h" }]],
      ["listEvidenceEnvelopeManifests", []],
      ["getEvidenceEnvelopeManifest", ["manifest/a b"]],
      ["verifyEvidenceEnvelopeManifest", ["manifest/a b"]],
      ["getEvidenceEnvelopePayload", ["manifest/a b"]],
      ["getBoundaryStatus", []],
      ["listBoundaryCapabilities", []],
      ["listBoundaryRecords", []],
      ["listBoundaryRecords", [{ limit: 10, offset: 0, empty: "", omitted: undefined }]],
      ["getBoundaryRecord", ["record/a b"]],
      ["verifyBoundaryRecord", ["record/a b"]],
      ["listBoundaryCheckpoints", []],
      ["createBoundaryCheckpoint", []],
      ["verifyBoundaryCheckpoint", ["checkpoint/a b"]],
      ["conformanceRun", [{ level: "basic" }]],
      ["getConformanceReport", ["report-1"]],
      ["listConformanceReports", []],
      ["listConformanceVectors", []],
      ["listNegativeConformanceVectors", []],
      ["listMcpRegistry", []],
      ["discoverMcpServer", [{ server_id: "srv" }]],
      ["approveMcpServer", [{ server_id: "srv", approver_id: "me", approval_receipt_id: "r" }]],
      ["getMcpRegistryRecord", ["srv/a b"]],
      ["approveMcpRegistryRecord", ["srv/a b", { reason: "ok" }]],
      ["revokeMcpRegistryRecord", ["srv/a b"]],
      ["revokeMcpRegistryRecord", ["srv/a b", "stale"]],
      ["scanMcpServer", [{ server_id: "srv" }]],
      ["listMcpAuthProfiles", []],
      ["putMcpAuthProfile", ["profile/a b", { scopes: ["tools"] }]],
      ["authorizeMcpCall", [{ tool: "read" }]],
      ["inspectSandboxGrants", []],
      ["inspectSandboxGrants", ["runtime", "profile", "epoch"]],
      ["listSandboxProfiles", []],
      ["listSandboxGrants", []],
      ["createSandboxGrant", [{ runtime: "wasi" }]],
      ["getSandboxGrant", ["grant/a b"]],
      ["verifySandboxGrant", ["grant/a b"]],
      ["preflightSandboxGrant", [{ runtime: "wasi" }]],
      ["listAgentIdentities", []],
      ["getAuthzHealth", []],
      ["checkAuthz", [{ subject: "agent" }]],
      ["listAuthzSnapshots", []],
      ["getAuthzSnapshot", ["snapshot/a b"]],
      ["listApprovalCeremonies", []],
      ["createApprovalCeremony", [{ approval_id: "a1" }]],
      ["transitionApprovalCeremony", ["approval/a b", "approve"]],
      ["transitionApprovalCeremony", ["approval/a b", "deny", { reason: "bad" }]],
      ["createApprovalWebAuthnChallenge", ["approval/a b"]],
      ["createApprovalWebAuthnChallenge", ["approval/a b", { user: "me" }]],
      ["assertApprovalWebAuthnChallenge", ["approval/a b", { credential: "c" }]],
      ["listBudgetCeilings", []],
      ["putBudgetCeiling", ["budget/a b", { limit: 1 }]],
      ["getCoexistenceCapabilities", []],
      ["getTelemetryOTelConfig", []],
      ["exportTelemetry", [{ span: "all" }]],
      ["health", []],
      ["version", []],
    ];

    for (const [method, args] of calls) {
      await (client as any)[method](...args);
    }

    expect(fetchSpy).toHaveBeenCalledTimes(calls.length);
    expect(fetchSpy.mock.calls.some(([url]) => String(url).includes("limit=10&offset=0"))).toBe(true);
    expect(fetchSpy.mock.calls.some(([url]) => String(url).includes("runtime=runtime&profile=profile&policy_epoch=epoch"))).toBe(true);
    expect(fetchSpy.mock.calls.every(([, init]) => init.headers.Authorization === "Bearer token")).toBe(true);
    expect(fetchSpy.mock.calls.every(([, init]) => init.headers["X-Helm-Tenant-ID"] === "tenant-a")).toBe(true);
    expect(fetchSpy.mock.calls.every(([, init]) => init.headers["X-Helm-Principal-ID"] === "principal-a")).toBe(true);
    expect(fetchSpy.mock.calls.every(([, init]) => init.headers["X-Helm-Session-ID"] === "session-a")).toBe(true);
    expect(fetchSpy.mock.calls.every(([, init]) => init.headers["X-Helm-Workspace-ID"] === "workspace-a")).toBe(true);
  });

  it("extracts governance headers and default values", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse(
      { id: "chatcmpl", choices: [] },
      200,
      {
        "X-Helm-Receipt-ID": "r1",
        "X-Helm-Status": "ALLOW",
        "X-Helm-Output-Hash": "oh",
        "X-Helm-Lamport-Clock": "9",
        "X-Helm-Reason-Code": "ALLOW",
        "X-Helm-Decision-ID": "d1",
        "X-Helm-ProofGraph-Node": "pg",
        "X-Helm-Signature": "sig",
        "X-Helm-Tool-Calls": "2",
      },
    ));
    await expect(client.chatCompletionsWithReceipt({ model: "gpt", messages: [] })).resolves.toMatchObject({
      governance: { receiptId: "r1", lamportClock: 9, toolCalls: 2 },
    });

    fetchSpy.mockResolvedValueOnce(jsonResponse({ id: "chatcmpl", choices: [] }));
    await expect(client.chatCompletionsWithReceipt({ model: "gpt", messages: [] })).resolves.toMatchObject({
      governance: { receiptId: "", lamportClock: 0, toolCalls: 0 },
    });
  });

  it("covers binary and form endpoints including error branches", async () => {
    const blob = new Blob(["bundle"]);
    fetchSpy.mockResolvedValueOnce(new Response("tgz", { status: 200 }));
    await expect(client.exportEvidence("session-1")).resolves.toBeInstanceOf(Blob);

    fetchSpy.mockResolvedValueOnce(helmError(400));
    await expect(client.exportEvidence()).rejects.toThrow(HelmApiError);

    fetchSpy.mockResolvedValueOnce(jsonResponse({ verdict: "PASS" }));
    await expect(client.verifyEvidence(blob)).resolves.toMatchObject({ verdict: "PASS" });

    fetchSpy.mockResolvedValueOnce(helmError(422));
    await expect(client.verifyEvidence(blob)).rejects.toThrow(HelmApiError);

    fetchSpy.mockResolvedValueOnce(jsonResponse({ verdict: "PASS" }));
    await expect(client.replayVerify(blob)).resolves.toMatchObject({ verdict: "PASS" });

    fetchSpy.mockResolvedValueOnce(helmError(422));
    await expect(client.replayVerify(blob)).rejects.toThrow(HelmApiError);
  });

  it("throws for JSON request and receipt failures", async () => {
    fetchSpy.mockResolvedValueOnce(helmError(403));
    await expect(client.health()).rejects.toThrow(HelmApiError);

    fetchSpy.mockResolvedValueOnce(helmError(403));
    await expect(client.chatCompletionsWithReceipt({ model: "gpt", messages: [] })).rejects.toThrow(HelmApiError);
  });
});
