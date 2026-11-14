// quantum_posture: regression checks for classical Ed25519 receipt verification only.
import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { HelmClient, verifyReceipt } from './index.js';

interface Vector { id: string; receipt: string; trusted_keys: string[]; valid: boolean; error?: string; verdict?: string; receipt_id?: string; }
const vectors: Vector[] = JSON.parse(readFileSync(new URL('../../../core/pkg/receiptverify/testdata/offline-verifier-vectors.json', import.meta.url), 'utf8')).vectors;

describe('offline receipt.v5 public API', () => {
  for (const vector of vectors) {
    it(vector.id, async () => {
      const result = await verifyReceipt(vector.receipt, vector.trusted_keys);
      expect(result.valid, result.detail).toBe(vector.valid);
      if (vector.valid) {
        expect(result.receiptId).toBe(vector.receipt_id);
        expect(result.verdict).toBe(vector.verdict);
        expect(result.error).toBeUndefined();
      } else {
        expect(result.error, result.detail).toBe(vector.error);
        expect(result.signed).toBeUndefined();
      }
    });
  }
  it('accepts raw bytes and named pinned keys without a transport', async () => {
    const v = vectors[0];
    const fetch = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('offline'));
    try {
      expect((await verifyReceipt(new TextEncoder().encode(v.receipt), { unrelated: v.trusted_keys[0] })).valid).toBe(true);
      expect((await verifyReceipt(v.receipt, `ed25519:${v.trusted_keys[0]}`)).valid).toBe(true);
      expect(fetch).not.toHaveBeenCalled();
    } finally { fetch.mockRestore(); }
  });
  it('refuses a leading UTF-8 BOM in the byte and string APIs', async () => {
    const v = vectors[0];
    const text = '\uFEFF' + v.receipt;
    expect((await verifyReceipt(new TextEncoder().encode(text), v.trusted_keys)).error).toBe('malformed');
    expect((await verifyReceipt(text, v.trusted_keys)).error).toBe('malformed');
  });
  it('refuses invalid UTF-8 even inside signed strings', async () => {
    const v = vectors[0];
    const raw = new TextEncoder().encode(v.receipt.replace('rcpt-001', 'Xcpt-001'));
    raw[raw.indexOf(88)] = 0xff;
    expect((await verifyReceipt(raw, v.trusted_keys)).error).toBe('malformed');
  });
  it('requires raw JSON so number spellings and duplicate names remain visible', async () => {
    const v = vectors[0];
    // @ts-expect-error already-decoded objects are deliberately outside the API
    expect((await verifyReceipt(JSON.parse(v.receipt) as object, v.trusted_keys)).error).toBe('malformed');
  });
  it('reports missing Ed25519 support without claiming signature rejection', async () => {
    const v = vectors[0];
    vi.stubGlobal('crypto', undefined);
    try { expect((await verifyReceipt(v.receipt, v.trusted_keys)).error).toBe('unsupported_runtime'); }
    finally { vi.unstubAllGlobals(); }
  });
});

it('fetches exact receipt bytes with authentication and an encoded path', async () => {
  const raw = '{"lamport_clock":1e0,"verdict":"ALLOW","verdict":"DENY"}';
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(raw));
  try {
    const client = new HelmClient({ baseUrl: 'https://example.invalid', apiKey: 'local-test-token' });
    expect(new TextDecoder().decode(await client.getReceiptJSON('id/a b'))).toBe(raw);
    expect(fetch.mock.calls[0][0]).toBe('https://example.invalid/api/v1/proofgraph/receipts/id%2Fa%20b');
    expect((fetch.mock.calls[0][1]?.headers as Record<string, string>).Authorization).toBe('Bearer local-test-token');
  } finally { fetch.mockRestore(); }
});
