# HELM SDK — TypeScript

Typed TypeScript/JavaScript client for the HELM kernel API. Zero runtime dependencies.

## Install

```bash
npm install @mindburn/helm
```

## Quick Example

```typescript
import { HelmClient } from '@mindburn/helm';

const helm = new HelmClient({ baseUrl: 'http://localhost:8080' });

// OpenAI-compatible chat (tool calls governed by HELM)
try {
  const res = await helm.chatCompletions({
    model: 'gpt-4',
    messages: [{ role: 'user', content: 'List files in /tmp' }],
  });
  console.log(res.choices[0].message.content);
} catch (err) {
  if (err instanceof HelmApiError) {
    console.log('Denied:', err.reasonCode); // e.g. DENY_TOOL_NOT_FOUND
  }
}

// Export + verify evidence pack
const pack = await helm.exportEvidence();
const result = await helm.verifyEvidence(pack);
console.log(result.verdict); // PASS

// Conformance
const conf = await helm.conformanceRun({ level: 'L2' });
console.log(conf.verdict, conf.gates, 'gates');
```

## API

| Method | Endpoint |
|--------|----------|
| `chatCompletions(req)` | `POST /v1/chat/completions` |
| `approveIntent(req)` | `POST /api/v1/kernel/approve` |
| `listSessions()` | `GET /api/v1/proofgraph/sessions` |
| `getReceipts(sessionId)` | `GET /api/v1/proofgraph/sessions/{id}/receipts` |
| `exportEvidence(sessionId?)` | `POST /api/v1/evidence/export` |
| `verifyEvidence(bundle)` | `POST /api/v1/evidence/verify` |
| `replayVerify(bundle)` | `POST /api/v1/replay/verify` |
| `conformanceRun(req)` | `POST /api/v1/conformance/run` |
| `health()` | `GET /healthz` |
| `version()` | `GET /version` |

## Error Handling

All errors throw `HelmApiError` with a typed `reasonCode`:
```typescript
try { await helm.chatCompletions(req); }
catch (e) { if (e instanceof HelmApiError) console.log(e.reasonCode); }
```
