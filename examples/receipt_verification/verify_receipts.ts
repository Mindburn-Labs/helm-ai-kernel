/**
 * HELM Receipt Verification Example (TypeScript SDK)
 *
 * Demonstrates how to:
 * 1. Connect to a HELM kernel
 * 2. List ProofGraph sessions
 * 3. Retrieve and verify receipts
 * 4. Export and verify evidence packs
 *
 * Prerequisites:
 *   npm install @mindburn/helm-ai-kernel
 */
import { createHash } from "crypto";

// Types matching HELM API
interface Receipt {
  receipt_id: string;
  decision_id: string;
  effect_id: string;
  executor_id: string;
  status: string;
  blob_hash: string;
  timestamp: string;
}

interface Session {
  session_id: string;
}

interface VerificationResult {
  outcome: "VERIFIED" | "FAILED" | "UNVERIFIABLE";
  checks_run: { name: string; status: string; detail: string }[];
  roots: { entry_count: number };
  errors: string[];
}

const BASE_URL = process.env.HELM_URL ?? "http://127.0.0.1:7714";
const API_KEY = process.env.HELM_API_KEY ?? "";

async function helmFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (API_KEY) {
    headers["Authorization"] = `Bearer ${API_KEY}`;
  }
  const resp = await fetch(`${BASE_URL}${path}`, { ...init, headers });
  if (!resp.ok) {
    throw new Error(`HELM API error ${resp.status}: ${await resp.text()}`);
  }
  return resp.json() as T;
}

function verifyHashLocally(receipt: Receipt): boolean {
  const payload = {
    decision_id: receipt.decision_id,
    effect_id: receipt.effect_id,
    executor_id: receipt.executor_id,
    status: receipt.status,
  };

  // JCS: sorted keys, compact separators
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  const hash =
    "sha256:" + createHash("sha256").update(canonical).digest("hex");

  return hash === receipt.blob_hash;
}

async function main(): Promise<void> {
  console.log("🔗 Connecting to HELM kernel at", BASE_URL);

  // Health check
  const health = await helmFetch<string>("/healthz");
  console.log("✅ Kernel healthy:", health);

  // List sessions
  const sessions = await helmFetch<Session[]>(
    "/api/v1/proofgraph/sessions"
  );
  console.log(`📋 Found ${sessions.length} ProofGraph sessions`);

  if (sessions.length === 0) {
    console.log("No sessions yet. Execute a tool call first.");
    return;
  }

  const session = sessions[0];
  console.log(`  → Using session: ${session.session_id}`);

  // Get receipts
  const receipts = await helmFetch<Receipt[]>(
    `/api/v1/proofgraph/sessions/${session.session_id}/receipts`
  );
  console.log(`🧾 Found ${receipts.length} receipts`);

  for (const receipt of receipts.slice(0, 3)) {
    console.log(`\n  Receipt: ${receipt.receipt_id}`);
    console.log(`  Status:  ${receipt.status}`);
    console.log(`  Hash:    ${receipt.blob_hash}`);

    const verified = verifyHashLocally(receipt);
    console.log(`  ${verified ? "✅" : "⚠️"} Local hash verify: ${verified}`);
  }

  // Export & verify evidence
  console.log("\n📦 Exporting evidence pack...");
  const authHeader: Record<string, string> = API_KEY ? { Authorization: `Bearer ${API_KEY}` } : {};
  const exported = await fetch(`${BASE_URL}/api/v1/evidence/export`, {
    method: "POST",
    headers: { ...authHeader, "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: session.session_id, format: "tar.gz" }),
  });
  if (!exported.ok) {
    throw new Error(`HELM API error ${exported.status}: ${await exported.text()}`);
  }
  const evidence = await exported.arrayBuffer();

  // The bundle is posted as raw bytes; the kernel checks it against its own
  // receipt signer and reports each check that ran.
  const verified = await fetch(`${BASE_URL}/api/v1/evidence/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: evidence,
  });
  if (!verified.ok) {
    throw new Error(`HELM API error ${verified.status}: ${await verified.text()}`);
  }
  const result = (await verified.json()) as VerificationResult;

  console.log(`\n🔍 Verification result:`);
  console.log(`  Outcome:   ${result.outcome}`);
  for (const check of result.checks_run) {
    console.log(`  ${check.name}: ${check.status} (${check.detail})`);
  }
  console.log(`  Receipts:  ${result.roots.entry_count}`);
  console.log(result.outcome === "VERIFIED" ? "\n✅ VERIFIED" : `\n❌ ${result.outcome}: ${result.errors.join("; ")}`);
}

main().catch(console.error);
