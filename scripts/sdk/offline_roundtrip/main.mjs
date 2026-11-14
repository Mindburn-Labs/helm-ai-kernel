import { readFileSync, writeFileSync } from 'node:fs';
import { HelmClient, verifyReceipt } from '../../../sdk/ts/dist/index.js';

if (process.argv[2] === '--offline') {
  for (const expected of ['ALLOW', 'DENY']) {
    const raw = readFileSync(`${process.env.HELM_SDK_EVIDENCE_DIR}/ts-${expected}.receipt.json`);
    const key = process.env.HELM_TRUSTED_RECEIPT_KEY;
    const result = await verifyReceipt(raw, key);
    if (!result.valid || result.verdict !== expected) throw new Error(`offline: ${JSON.stringify(result)}`);
    const changed = { ...JSON.parse(raw.toString('utf8')), verdict: 'TAMPERED' };
    if ((await verifyReceipt(JSON.stringify(changed), key)).valid) throw new Error('tampered receipt verified');
    if ((await verifyReceipt(raw, '00'.repeat(32))).valid) throw new Error('wrong key verified');
    console.log(JSON.stringify({ sdk: 'ts', offline: true, valid: true, verdict: expected }));
  }
  process.exit(0);
}

const helm = new HelmClient({
  baseUrl: process.env.HELM_URL, apiKey: process.env.HELM_ADMIN_API_KEY,
  tenantId: 'sdk-offline-tenant', principalId: 'sdk-offline-principal',
});
for (const [tool, effect_level, expected] of [
  ['read-ticket', 'ticket:SDK-100', 'ALLOW'],
  ['dangerous-shell', 'system:shell', 'DENY'],
]) {
  const decision = await helm.evaluateDecisionV5({ tool, effect_level, session_id: 'ts-offline-sdk' });
  if (decision.verdict !== expected || !decision.receipt_id) throw new Error(`evaluate: ${JSON.stringify(decision)}`);
  const raw = await helm.getReceiptJSON(decision.receipt_id);
  const result = await verifyReceipt(raw, process.env.HELM_TRUSTED_RECEIPT_KEY);
  if (!result.valid || result.verdict !== expected || result.receiptId !== decision.receipt_id) throw new Error(`offline: ${JSON.stringify(result)}`);
  if ((await verifyReceipt(raw, '00'.repeat(32))).valid) throw new Error('wrong key verified');
  if (process.env.HELM_SDK_EVIDENCE_DIR) writeFileSync(`${process.env.HELM_SDK_EVIDENCE_DIR}/ts-${expected}.receipt.json`, raw);
  console.log(JSON.stringify({ sdk: 'ts', verdict: result.verdict, receipt_id: result.receiptId, valid: result.valid }));
}
