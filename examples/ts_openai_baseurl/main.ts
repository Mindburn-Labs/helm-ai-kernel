// HELM SDK Example — TypeScript
// Shows: chat completions, denial handling, conformance.
// Run: npx tsx main.ts  (or compile with tsc first)

import { HelmClient, HelmApiError } from '../../sdk/ts/src/index.js';

const HELM_URL = process.env.HELM_URL || 'http://localhost:8080';

async function main() {
  const helm = new HelmClient({ baseUrl: HELM_URL });

  // 1. Chat completions (governed by HELM)
  console.log('=== Chat Completions ===');
  try {
    const res = await helm.chatCompletions({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'List files in /tmp' }],
    });
    console.log('Response:', res.choices[0]?.message?.content ?? 'no content');
  } catch (err) {
    if (err instanceof HelmApiError) {
      console.log('Denied:', err.reasonCode, '-', err.message);
    } else {
      console.error(err);
    }
  }

  // 2. Export + verify evidence
  console.log('\n=== Evidence ===');
  try {
    const pack = await helm.exportEvidence();
    console.log('Exported:', pack.size, 'bytes');
    const result = await helm.verifyEvidence(pack);
    console.log('Verification:', result.verdict);
  } catch (err) {
    if (err instanceof HelmApiError) {
      console.log('Evidence error:', err.reasonCode);
    }
  }

  // 3. Conformance
  console.log('\n=== Conformance ===');
  try {
    const conf = await helm.conformanceRun({ level: 'L2' });
    console.log('Verdict:', conf.verdict, 'Gates:', conf.gates, 'Failed:', conf.failed);
  } catch (err) {
    if (err instanceof HelmApiError) {
      console.log('Conformance error:', err.reasonCode);
    }
  }

  // 4. Health
  console.log('\n=== Health ===');
  try {
    const h = await helm.health();
    console.log('Status:', h);
  } catch (err) {
    console.log('Health check failed:', err);
  }
}

main().catch(console.error);
