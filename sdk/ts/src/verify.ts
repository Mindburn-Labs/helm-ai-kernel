// Offline verification of HELM receipt.v5 signatures.
//
// quantum_posture: classical Ed25519 only; no hybrid or post-quantum claim.
//
// verifyReceipt answers one question without contacting HELM: did the holder
// of a key you trust sign this receipt, and do its signed members say what the
// receipt says? It uses only WebCrypto (Ed25519) and reads no network, clock or
// environment. It checks the receipt.v5 signed envelope: one JSON
// object with no duplicate member and no letter-case variant of a signed
// member; signature_version "receipt.v5" (an unversioned legacy receipt is
// refused); the thirteen signed members with their wire types; lamport_clock
// an integer in [0, 2^53-1]; signature_profile and signature_algorithm both
// empty or exactly classical/ed25519; and the Ed25519 signature over the RFC
// 8785 canonical JSON of the signed members under one of the trusted keys.
// key_id is a hint, never a filter, and the receipt's own public_key_set is
// never trusted. Chain linkage, permits and gateway bindings are
// receipt_verify's. Unsigned metadata schemas are not validated. Only signed
// contains authenticated fields. keyId is an unsigned claim. Invalid UTF-8
// is refused.
//
// The shared vectors in
// core/pkg/receiptverify/testdata/offline-verifier-vectors.json hold this
// module, the Go and Python SDKs and receipt_verify to the same verdicts.

import { checkReceiptMemberNames } from './verify-members.js';

export const RECEIPT_SIGNATURE_V5 = 'receipt.v5';
const MAX_SAFE_INTEGER = '9007199254740991';

/** The receipt.v5 signed members in RFC 8785 order (all ASCII). */
const SIGNED_MEMBERS = [
  'args_hash', 'decision_id', 'effect_id', 'lamport_clock', 'output_hash', 'policy_hash',
  'prev_hash', 'reason_code', 'receipt_id', 'session_id', 'signature_version', 'status', 'verdict',
] as const;

const MAX_DEPTH = 64;

/** verifyReceipt's verdict. `valid` is true only when every check passed. */
export interface ReceiptVerification {
  valid: boolean;
  /** The first check that failed: malformed, duplicate_member, shadow_member, unsupported_version, missing_member, non_interoperable_number, signature_metadata, unsigned, no_trusted_key, bad_key or signature_rejected. */
  error?: string;
  detail: string;
  receiptId?: string;
  verdict?: string;
  reasonCode?: string;
  keyId?: string;
  signed?: Record<string, string | number>;
}

/** Trusted Ed25519 public keys: one hex key, a list, or key id to key. */
export type TrustedKeys = string | readonly string[] | Readonly<Record<string, string>>;

class Refusal extends Error {
  constructor(readonly code: string, detail: string) {
    super(detail);
  }
}

class JsonNumber {
  constructor(readonly literal: string) {}
}

type JsonValue = null | boolean | string | JsonNumber | JsonValue[] | { [key: string]: JsonValue };

/** A JSON parser that keeps number literals as written and refuses duplicate members. */
function parseStrict(text: string): JsonValue {
  let i = 0;
  const malformed = (what: string): never => {
    throw new Refusal('malformed', `receipt is not JSON: ${what} at offset ${i}`);
  };
  const skip = () => {
    while (i < text.length && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++;
  };
  const literal = (word: string, value: JsonValue): JsonValue => {
    if (!text.startsWith(word, i)) malformed('unexpected token');
    i += word.length;
    return value;
  };
  const number = (): JsonNumber => {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (!match) malformed('invalid number');
    i += match![0].length;
    return new JsonNumber(match![0]);
  };
  const string = (): string => {
    i++; // opening quote
    let out = '';
    for (;;) {
      if (i >= text.length) malformed('unterminated string');
      const ch = text[i];
      if (ch === '"') {
        i++;
        return out.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/gu, '\uFFFD');
      }
      if (ch.charCodeAt(0) < 0x20) malformed('control character in string');
      if (ch !== '\\') {
        out += ch;
        i++;
        continue;
      }
      const esc = text[i + 1];
      i += 2;
      switch (esc) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u': {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) malformed('invalid \\u escape');
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
          break;
        }
        default:
          malformed('invalid escape');
      }
    }
  };
  const value = (depth: number): JsonValue => {
    skip();
    const ch = text[i];
    if ((ch === '{' || ch === '[') && depth >= MAX_DEPTH) malformed('nesting too deep');
    if (ch === '{') {
      i++;
      const object: { [key: string]: JsonValue } = Object.create(null);
      skip();
      if (text[i] === '}') {
        i++;
        return object;
      }
      for (;;) {
        skip();
        if (text[i] !== '"') malformed('expected a member name');
        const key = string();
        if (Object.prototype.hasOwnProperty.call(object, key)) {
          throw new Refusal('duplicate_member', `duplicate object member ${JSON.stringify(key)}`);
        }
        skip();
        if (text[i] !== ':') malformed("expected ':'");
        i++;
        object[key] = value(depth + 1);
        skip();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === '}') {
          i++;
          return object;
        }
        malformed("expected ',' or '}'");
      }
    }
    if (ch === '[') {
      i++;
      const array: JsonValue[] = [];
      skip();
      if (text[i] === ']') {
        i++;
        return array;
      }
      for (;;) {
        array.push(value(depth + 1));
        skip();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === ']') {
          i++;
          return array;
        }
        malformed("expected ',' or ']'");
      }
    }
    if (ch === '"') return string();
    if (ch === 't') return literal('true', true);
    if (ch === 'f') return literal('false', false);
    if (ch === 'n') return literal('null', null);
    if (ch === '-' || (ch >= '0' && ch <= '9')) return number();
    return malformed('unexpected token');
  };
  const result = value(0);
  skip();
  if (i !== text.length) throw new Refusal('malformed', 'receipt has a value after the first');
  return result;
}

function jcsString(value: string): string {
  let out = '"';
  for (const ch of value) {
    const code = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\b') out += '\\b';
    else if (ch === '\f') out += '\\f';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (code < 0x20) out += `\\u${code.toString(16).padStart(4, '0')}`;
    else out += ch;
  }
  return `${out}"`;
}

/** The RFC 8785 canonical bytes a receipt.v5 signature covers. */
function receiptSigningPayload(signed: Readonly<Record<string, string | number>>): Uint8Array {
  const members = SIGNED_MEMBERS.map((member) => {
    const value = signed[member];
    return `"${member}":${member === 'lamport_clock' ? String(value) : jcsString(String(value))}`;
  });
  // TextEncoder writes an unpaired surrogate as U+FFFD, as encoding/json and the signer do.
  return new TextEncoder().encode(`{${members.join(',')}}`);
}

function hexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let j = 0; j < out.length; j++) out[j] = parseInt(hex.slice(2 * j, 2 * j + 2), 16);
  return out;
}

function documentOf(receipt: string | Uint8Array): JsonValue {
  if (typeof receipt === 'string') {
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/gu.test(receipt)) throw new Refusal('malformed', 'receipt document must contain Unicode scalar values');
    return parseStrict(receipt);
  }
  if (receipt instanceof Uint8Array) {
    let text: string;
    try {
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(receipt);
    } catch {
      throw new Refusal('malformed', 'receipt document must be UTF-8');
    }
    return parseStrict(text);
  }
  throw new Refusal('malformed', 'receipt must be raw JSON text or bytes');
}

function checkMembers(document: JsonValue): { signed: Record<string, string | number>; keyId: string; signature: Uint8Array } {
  if (document === null || typeof document !== 'object' || Array.isArray(document) || document instanceof JsonNumber) {
    throw new Refusal('malformed', 'receipt must be a JSON object');
  }
  const receipt = document as { [key: string]: JsonValue };
  if (Object.prototype.hasOwnProperty.call(receipt, 'receipts')) throw new Refusal('malformed', 'input must be one receipt object, not a bundle');
  checkReceiptMemberNames(receipt, Refusal);
  const has = (member: string) => Object.prototype.hasOwnProperty.call(receipt, member);
  if (!has('signature_version')) {
    throw new Refusal('unsupported_version', 'receipt has no signature_version; legacy receipts are not verified here');
  }
  if (receipt.signature_version !== RECEIPT_SIGNATURE_V5) {
    throw new Refusal('unsupported_version', `unsupported receipt signature version ${JSON.stringify(receipt.signature_version)}`);
  }
  const signed: Record<string, string | number> = {};
  for (const member of SIGNED_MEMBERS) {
    if (!has(member)) throw new Refusal('missing_member', `receipt.v5 missing signed member ${JSON.stringify(member)}`);
    const value = receipt[member];
    if (member === 'lamport_clock') {
      if (!(value instanceof JsonNumber)) {
        throw new Refusal('missing_member', 'receipt.v5 signed member "lamport_clock" must be an unsigned integer');
      }
      if (!/^(0|[1-9][0-9]*)$/.test(value.literal) || (value.literal.length > 16 || (value.literal.length === 16 && value.literal > MAX_SAFE_INTEGER))) {
        throw new Refusal('non_interoperable_number', `lamport_clock ${value.literal} is not an integer in [0, 2^53-1]`);
      }
      signed[member] = Number(value.literal);
      continue;
    }
    if (typeof value !== 'string') {
      throw new Refusal('missing_member', `receipt.v5 signed member ${JSON.stringify(member)} must be a string`);
    }
    signed[member] = value;
  }
  const profile = has('signature_profile') ? receipt.signature_profile : '';
  const algorithm = has('signature_algorithm') ? receipt.signature_algorithm : '';
  if (!((profile === '' && algorithm === '') || (profile === 'classical' && algorithm === 'ed25519'))) {
    throw new Refusal('signature_metadata', 'signature metadata must be both empty or exactly classical/ed25519');
  }
  const signature = receipt.signature;
  if (typeof signature !== 'string' || signature === '') throw new Refusal('unsigned', 'receipt carries no signature');
  if (!/^[0-9a-fA-F]{128}$/.test(signature)) throw new Refusal('signature_rejected', 'signature is not 64 bytes of hex');
  const keyId = typeof receipt.key_id === 'string' ? receipt.key_id : '';
  return { signed, keyId, signature: hexBytes(signature) };
}

function trustedKeyBytes(keys: TrustedKeys): Uint8Array[] {
  const values = typeof keys === 'string' ? [keys] : Array.isArray(keys) ? [...keys] : Object.values(keys as Record<string, string>);
  if (values.length === 0) throw new Refusal('no_trusted_key', 'no trusted public key supplied');
  return values.map((value) => {
    const text = typeof value === 'string' ? value.trim().replace(/^ed25519:/, '') : '';
    if (!/^[0-9a-fA-F]{64}$/.test(text)) throw new Refusal('bad_key', 'a trusted key must be a 32-byte Ed25519 public key in hex');
    return hexBytes(text);
  });
}

async function ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Refusal('unsupported_runtime', 'WebCrypto is unavailable; Ed25519 verification needs crypto.subtle');
  try {
    const key = await subtle.importKey('raw', publicKey as BufferSource, { name: 'Ed25519' }, false, ['verify']);
    return await subtle.verify({ name: 'Ed25519' }, key, signature as BufferSource, message as BufferSource);
  } catch (error) {
    if (error instanceof Error && error.name === 'NotSupportedError') throw new Refusal('unsupported_runtime', 'WebCrypto Ed25519 is unavailable');
    // A key that is not a curve point verifies nothing, as in crypto/ed25519.
    return false;
  }
}

/**
 * Verify one receipt.v5 offline against keys you obtained out of band.
 *
 * Pass the receipt as the raw JSON text the server returned:
 * duplicate members are only visible there. A key served by the HELM that
 * signed the receipt is HELM vouching for itself: pin it once, out of band.
 */
export async function verifyReceipt(receipt: string | Uint8Array, trustedKeys: TrustedKeys): Promise<ReceiptVerification> {
  try {
    const { signed, keyId, signature } = checkMembers(documentOf(receipt));
    const keys = trustedKeyBytes(trustedKeys);
    const payload = receiptSigningPayload(signed);
    for (const key of keys) {
      if (await ed25519Verify(key, payload, signature)) {
        return {
          valid: true,
          detail: 'the receipt.v5 signature verifies under a trusted key',
          receiptId: signed.receipt_id as string,
          verdict: signed.verdict as string,
          reasonCode: signed.reason_code as string,
          keyId,
          signed,
        };
      }
    }
    throw new Refusal('signature_rejected', 'signature does not verify under any trusted key');
  } catch (err) {
    if (err instanceof Refusal) return { valid: false, error: err.code, detail: err.message };
    throw err;
  }
}
