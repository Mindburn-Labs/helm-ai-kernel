import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { HelmClient, HelmApiError } from './client.js';
import type { HelmClientConfig } from './client.js';

// ── Helpers ─────────────────────────────────────────────

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function errorResponse(status: number, reasonCode = 'ERROR_INTERNAL', message = 'boom'): Response {
  return jsonResponse(
    { error: { message, type: 'internal_error', code: 'err', reason_code: reasonCode } },
    status,
  );
}

// ── Tests ───────────────────────────────────────────────

describe('HelmApiError', () => {
  it('exposes status, reasonCode, details, and message', () => {
    const err = new HelmApiError(403, {
      error: {
        message: 'denied',
        type: 'permission_denied',
        code: 'DENY',
        reason_code: 'DENY_POLICY_VIOLATION',
        details: { policy: 'no-writes' },
      },
    });
    expect(err.status).toBe(403);
    expect(err.reasonCode).toBe('DENY_POLICY_VIOLATION');
    expect(err.details).toEqual({ policy: 'no-writes' });
    expect(err.message).toBe('denied');
    expect(err.name).toBe('HelmApiError');
  });
});

describe('HelmClient', () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── Constructor ─────────────────────────────────────
  describe('constructor', () => {
    it('strips trailing slash from baseUrl', () => {
      const client = new HelmClient({ baseUrl: 'http://host:8080/' });
      // Verify via a call that the URL has no double slash
      fetchSpy.mockResolvedValue(jsonResponse({ status: 'ok' }));
      client.health();
      expect(fetchSpy).toHaveBeenCalledWith(
        'http://host:8080/healthz',
        expect.anything(),
      );
    });

    it('sets Authorization header when apiKey provided', () => {
      const client = new HelmClient({ baseUrl: 'http://h', apiKey: 'sk-test' });
      fetchSpy.mockResolvedValue(jsonResponse({ status: 'ok' }));
      client.health();
      const callArgs = fetchSpy.mock.calls[0][1];
      expect(callArgs.headers['Authorization']).toBe('Bearer sk-test');
    });

    it('omits Authorization header when apiKey not provided', () => {
      const client = new HelmClient({ baseUrl: 'http://h' });
      fetchSpy.mockResolvedValue(jsonResponse({ status: 'ok' }));
      client.health();
      const callArgs = fetchSpy.mock.calls[0][1];
      expect(callArgs.headers['Authorization']).toBeUndefined();
    });
  });

  // ── Error handling ──────────────────────────────────
  describe('error handling', () => {
    it('throws HelmApiError on non-2xx response', async () => {
      fetchSpy.mockResolvedValue(errorResponse(500));
      const client = new HelmClient({ baseUrl: 'http://h' });
      await expect(client.health()).rejects.toThrow(HelmApiError);
    });

    it('populates error fields from response body', async () => {
      fetchSpy.mockResolvedValue(errorResponse(422, 'DENY_SCHEMA_MISMATCH', 'bad schema'));
      const client = new HelmClient({ baseUrl: 'http://h' });
      try {
        await client.health();
        expect.unreachable('should have thrown');
      } catch (e) {
        const err = e as HelmApiError;
        expect(err.status).toBe(422);
        expect(err.reasonCode).toBe('DENY_SCHEMA_MISMATCH');
        expect(err.message).toBe('bad schema');
      }
    });
  });

  // ── chatCompletions ─────────────────────────────────
  describe('chatCompletions', () => {
    it('POSTs to /v1/chat/completions with request body', async () => {
      const mockRes = { id: 'chatcmpl-1', object: 'chat.completion', created: 1, model: 'gpt-4', choices: [] };
      fetchSpy.mockResolvedValue(jsonResponse(mockRes));
      const client = new HelmClient({ baseUrl: 'http://h' });

      const result = await client.chatCompletions({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'hi' }],
      });

      expect(fetchSpy).toHaveBeenCalledWith(
        'http://h/v1/chat/completions',
        expect.objectContaining({ method: 'POST' }),
      );
      expect(result.id).toBe('chatcmpl-1');
    });
  });

  // ── approveIntent ───────────────────────────────────
  describe('approveIntent', () => {
    it('POSTs to /api/v1/kernel/approve', async () => {
      const receipt = {
        receipt_id: 'r1', decision_id: 'd1', effect_id: 'e1',
        status: 'APPROVED', reason_code: 'ALLOW', output_hash: 'h',
        blob_hash: 'b', prev_hash: 'p', lamport_clock: 1,
        signature: 's', timestamp: 't', principal: 'pr',
      };
      fetchSpy.mockResolvedValue(jsonResponse(receipt));
      const client = new HelmClient({ baseUrl: 'http://h' });

      const result = await client.approveIntent({
        intent_hash: 'abc', signature_b64: 's', public_key_b64: 'pk',
      });

      expect(fetchSpy).toHaveBeenCalledWith(
        'http://h/api/v1/kernel/approve',
        expect.objectContaining({ method: 'POST' }),
      );
      expect(result.receipt_id).toBe('r1');
      expect(result.status).toBe('APPROVED');
    });
  });

  // ── ProofGraph ──────────────────────────────────────
  describe('listSessions', () => {
    it('GETs /api/v1/proofgraph/sessions with query params', async () => {
      fetchSpy.mockResolvedValue(jsonResponse([]));
      const client = new HelmClient({ baseUrl: 'http://h' });
      await client.listSessions(10, 5);
      expect(fetchSpy).toHaveBeenCalledWith(
        'http://h/api/v1/proofgraph/sessions?limit=10&offset=5',
        expect.objectContaining({ method: 'GET' }),
      );
    });
  });

  describe('getReceipts', () => {
    it('GETs receipts for a session', async () => {
      fetchSpy.mockResolvedValue(jsonResponse([]));
      const client = new HelmClient({ baseUrl: 'http://h' });
      await client.getReceipts('sess-1');
      expect(fetchSpy).toHaveBeenCalledWith(
        'http://h/api/v1/proofgraph/sessions/sess-1/receipts',
        expect.objectContaining({ method: 'GET' }),
      );
    });
  });

  describe('getReceipt', () => {
    it('GETs a single receipt by hash', async () => {
      const receipt = {
        receipt_id: 'r1', decision_id: 'd1', effect_id: 'e1',
        status: 'APPROVED', reason_code: 'ALLOW', output_hash: 'h',
        blob_hash: 'b', prev_hash: 'p', lamport_clock: 1,
        signature: 's', timestamp: 't', principal: 'pr',
      };
      fetchSpy.mockResolvedValue(jsonResponse(receipt));
      const client = new HelmClient({ baseUrl: 'http://h' });
      const result = await client.getReceipt('hash-abc');
      expect(fetchSpy).toHaveBeenCalledWith(
        'http://h/api/v1/proofgraph/receipts/hash-abc',
        expect.objectContaining({ method: 'GET' }),
      );
      expect(result.receipt_id).toBe('r1');
    });
  });

  // ── Conformance ─────────────────────────────────────
  describe('conformanceRun', () => {
    it('POSTs to /api/v1/conformance/run', async () => {
      const report = { report_id: 'rpt1', level: 'L1', verdict: 'PASS', gates: 12, failed: 0, details: {} };
      fetchSpy.mockResolvedValue(jsonResponse(report));
      const client = new HelmClient({ baseUrl: 'http://h' });
      const result = await client.conformanceRun({ level: 'L1' });
      expect(result.verdict).toBe('PASS');
      expect(result.gates).toBe(12);
    });
  });

  describe('getConformanceReport', () => {
    it('GETs conformance report by ID', async () => {
      const report = { report_id: 'rpt1', level: 'L1', verdict: 'PASS', gates: 12, failed: 0, details: {} };
      fetchSpy.mockResolvedValue(jsonResponse(report));
      const client = new HelmClient({ baseUrl: 'http://h' });
      const result = await client.getConformanceReport('rpt1');
      expect(fetchSpy).toHaveBeenCalledWith(
        'http://h/api/v1/conformance/reports/rpt1',
        expect.objectContaining({ method: 'GET' }),
      );
      expect(result.report_id).toBe('rpt1');
    });
  });

  // ── System ──────────────────────────────────────────
  describe('health', () => {
    it('GETs /healthz', async () => {
      fetchSpy.mockResolvedValue(jsonResponse({ status: 'ok', version: '0.1.0' }));
      const client = new HelmClient({ baseUrl: 'http://h' });
      const result = await client.health();
      expect(result.status).toBe('ok');
      expect(result.version).toBe('0.1.0');
    });
  });

  describe('version', () => {
    it('GETs /version', async () => {
      const info = { version: '0.1.0', commit: 'abc123', build_time: '2026-01-01T00:00:00Z', go_version: '1.24' };
      fetchSpy.mockResolvedValue(jsonResponse(info));
      const client = new HelmClient({ baseUrl: 'http://h' });
      const result = await client.version();
      expect(result.version).toBe('0.1.0');
      expect(result.commit).toBe('abc123');
    });
  });
});

// ── Re-exports ────────────────────────────────────────
describe('index re-exports', () => {
  it('exports HelmClient and HelmApiError', async () => {
    const mod = await import('./index.js');
    expect(mod.HelmClient).toBeDefined();
    expect(mod.HelmApiError).toBeDefined();
  });
});
