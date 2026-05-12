import type { SurfaceRecord } from '../../sdk/ts/dist/index.js';

declare const process: { env: Record<string, string | undefined>; cwd(): string };

const { HelmClient, HelmApiError } = await import(`${process.cwd()}/sdk/ts/dist/index.js`) as typeof import('../../sdk/ts/dist/index.js');

const CANONICAL_VERDICTS = new Set(['ALLOW', 'DENY', 'ESCALATE']);

function requireVerdict(record: SurfaceRecord, expected: string, label: string): string {
  const verdict = String(record.verdict ?? '');
  if (!CANONICAL_VERDICTS.has(verdict)) {
    throw new Error(`${label}: non-canonical verdict ${verdict}`);
  }
  if (verdict !== expected) {
    throw new Error(`${label}: got ${verdict}, want ${expected}`);
  }
  return verdict;
}

function requireReceipt(record: SurfaceRecord, label: string): SurfaceRecord {
  const receipt = record.receipt as SurfaceRecord | undefined;
  const proofRefs = record.proof_refs as SurfaceRecord | undefined;
  if (!receipt) throw new Error(`${label}: receipt missing`);
  if (!receipt.receipt_id) throw new Error(`${label}: receipt_id missing`);
  if (!receipt.signature) throw new Error(`${label}: signature missing`);
  if (!proofRefs?.receipt_hash) throw new Error(`${label}: proof_refs.receipt_hash missing`);
  const metadata = receipt.metadata as SurfaceRecord | undefined;
  if (metadata?.side_effect_dispatched !== false) {
    throw new Error(`${label}: side effects must remain undispatched`);
  }
  return receipt;
}

async function requireMcpDenial(client: InstanceType<typeof HelmClient>): Promise<string> {
  try {
    await client.authorizeMcpCall({
      server_id: 'unknown-ts-sdk-fixture',
      tool_name: 'local.echo',
      args_hash: 'sha256:ts-sdk-local-only',
    });
  } catch (err) {
    if (!(err instanceof HelmApiError)) throw err;
    const body = (err.body ?? {}) as SurfaceRecord;
    const verdict = String(body.verdict ?? 'DENY');
    if (verdict !== 'DENY' && verdict !== 'ESCALATE') {
      throw new Error(`MCP denial returned ${verdict}, expected DENY or ESCALATE`);
    }
    return verdict;
  }
  throw new Error('MCP authorization unexpectedly allowed an unknown server');
}

const helmUrl = process.env.HELM_URL ?? 'http://127.0.0.1:7715';
const helm = new HelmClient({
  baseUrl: helmUrl,
  apiKey: process.env.HELM_ADMIN_API_KEY,
  tenantId: process.env.HELM_TENANT_ID ?? 'sdk-ts-example',
});

const allowed = await helm.evaluateDecision({
  principal: 'sdk-ts-agent',
  action: 'read-ticket',
  resource: 'ticket:SDK-200',
  context: { example: 'ts-sdk' },
});
const denied = await helm.evaluateDecision({
  principal: 'sdk-ts-agent',
  action: 'dangerous-shell',
  resource: 'system:shell',
  context: { example: 'ts-sdk' },
});
requireVerdict(allowed, 'ALLOW', 'allowed tool call');
requireVerdict(denied, 'DENY', 'denied dangerous action');

const demo = await helm.runPublicDemo('read_ticket');
const receipt = requireReceipt(demo, 'signed receipt');
const proofRefs = demo.proof_refs as SurfaceRecord;
const verification = await helm.verifyPublicDemoReceipt(receipt, String(proofRefs.receipt_hash));
if (verification.valid !== true) {
  throw new Error(`receipt verification failed: ${JSON.stringify(verification)}`);
}

const mcpVerdict = await requireMcpDenial(helm);
const preflight = await helm.preflightSandboxGrant({
  runtime: 'wazero',
  profile: 'sdk-ts-example',
  image_digest: `sha256:${'b'.repeat(64)}`,
  policy_epoch: 'sdk-ts-example',
});
requireVerdict(preflight, 'ALLOW', 'sandbox preflight');

const evidence = await helm.exportEvidence('sdk-ts-agent');
const evidenceResult = await helm.verifyEvidence(evidence);
if (evidenceResult.verdict !== 'PASS') {
  throw new Error(`evidence verification failed: ${JSON.stringify(evidenceResult)}`);
}

console.log(JSON.stringify({
  sdk: 'typescript',
  allowed: allowed.verdict,
  denied: denied.verdict,
  mcp_unknown_server: mcpVerdict,
  receipt_verified: true,
  sandbox_preflight: preflight.verdict,
  evidence_verification: evidenceResult.verdict,
}, null, 2));
