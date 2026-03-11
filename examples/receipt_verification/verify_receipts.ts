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
 *   npm install @mindburn/helm
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
  valid: boolean;
  integrity_check: string;
  receipt_count: number;
}

const BASE_URL = process.env.HELM_URL ?? "http://localhost:8080";
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
  const evidence = await helmFetch<ArrayBuffer>(
    "/api/v1/evidence/export",
    {
      method: "POST",
      body: JSON.stringify({
        session_id: session.session_id,
        format: "tar.gz",
      }),
    }
  );

  const result = await helmFetch<VerificationResult>(
    "/api/v1/evidence/verify",
    {
      method: "POST",
      body: JSON.stringify({
        bundle_b64: Buffer.from(evidence).toString("base64"),
      }),
    }
  );

  console.log(`\n🔍 Verification result:`);
  console.log(`  Valid:     ${result.valid}`);
  console.log(`  Integrity: ${result.integrity_check}`);
  console.log(`  Receipts:  ${result.receipt_count}`);
  console.log(result.valid ? "\n✅ VERIFIED" : "\n❌ FAILED");
}

main().catch(console.error);
