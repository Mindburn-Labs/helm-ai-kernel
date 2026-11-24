import { HelmClient } from '../../sdk/ts/dist/index.js';

declare const process: { env: Record<string, string | undefined>; exitCode?: number };

async function main(): Promise<void> {
  const helm = new HelmClient({
    baseUrl: process.env.HELM_URL ?? 'http://127.0.0.1:7714',
    apiKey: process.env.HELM_ADMIN_API_KEY || process.env.HELM_API_KEY,
    tenantId: process.env.HELM_TENANT_ID,
    principalId: process.env.HELM_PRINCIPAL_ID,
  });

  const [session] = await helm.listSessions(1);
  if (!session) {
    console.log('No ProofGraph sessions. Evaluate a tool call first.');
    return;
  }
  if (!session.session_id) {
    throw new Error('The server did not return a session ID.');
  }

  const receipts = await helm.getReceipts(session.session_id);
  console.log(`ProofGraph session ${session.session_id} has ${receipts.length} receipts`);
  for (const receipt of receipts.slice(0, 3)) {
    console.log(`  ${receipt.receipt_id}  ${receipt.status}  input snapshot ${receipt.blob_hash || '-'}`);
  }

  const evidence = await helm.exportEvidence(session.session_id);
  const result = await helm.verifyEvidence(evidence);
  console.log(`Server-side EvidencePack verification: ${result.outcome}`);
  for (const check of result.checks_run) {
    console.log(`  ${check.name}: ${check.status} (${check.detail})`);
  }
  for (const error of result.errors) {
    console.error(error);
  }
  if (result.outcome !== 'VERIFIED') {
    process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
