// evidencepack.js — EvidencePack manifest parsing and blob verification.
//
// An EvidencePack TAR contains:
//   - manifest.json       (JCS-canonicalized map: relative_path -> sha256 hex)
//   - <content blobs>     referenced by manifest paths (decisions/, receipts/, proofgraph/, ...)
//   - signature.sig       optional Ed25519 signature over manifest.json (not verified here; use `helm verify`)
//
// This module verifies that each blob's SHA-256 matches the manifest entry.
// We do NOT verify the Ed25519 signature in-browser (requires trust-root key management);
// direct users to `helm verify` for signature verification.

import { findEntry, decodeText } from "./tar-reader.js";

/**
 * Load and parse the manifest from a TAR entry list.
 * @param {Array} entries
 * @returns {object|null}
 */
export function loadManifest(entries) {
  const body = findEntry(entries, "manifest.json");
  if (!body) return null;
  try {
    return JSON.parse(decodeText(body));
  } catch {
    return null;
  }
}

/**
 * Verify each manifest-listed blob's SHA-256 digest.
 * @returns {Promise<Array<{path: string, expected: string, actual: string|null, ok: boolean}>>}
 */
export async function verifyBlobs(entries, manifest) {
  const results = [];
  const files = normalizeManifestFiles(manifest);

  for (const { path, expected } of files) {
    const body = findEntry(entries, path);
    if (!body) {
      results.push({ path, expected, actual: null, ok: false });
      continue;
    }
    const actual = await sha256Hex(body);
    results.push({
      path,
      expected,
      actual,
      ok: normalizeHash(expected) === actual,
    });
  }
  return results;
}

/**
 * Extract decision records from the pack, if present.
 * @returns {Array<object>}
 */
export function loadDecisions(entries) {
  const candidatePaths = [
    "decisions.json",
    "decisions.jsonl",
    "decisions/decisions.json",
  ];
  for (const p of candidatePaths) {
    const body = findEntry(entries, p);
    if (!body) continue;
    const text = decodeText(body);
    if (p.endsWith(".jsonl")) {
      return text
        .split("\n")
        .filter((l) => l.trim())
        .map(safeJSONParse)
        .filter(Boolean);
    }
    const parsed = safeJSONParse(text);
    if (Array.isArray(parsed)) return parsed;
    if (parsed && Array.isArray(parsed.decisions)) return parsed.decisions;
  }
  return [];
}

/**
 * Extract ProofGraph nodes, if present.
 * @returns {Array<object>}
 */
export function loadProofGraph(entries) {
  const candidatePaths = [
    "proofgraph.json",
    "proofgraph.jsonl",
    "proofgraph/nodes.json",
    "proofgraph/nodes.jsonl",
  ];
  for (const p of candidatePaths) {
    const body = findEntry(entries, p);
    if (!body) continue;
    const text = decodeText(body);
    if (p.endsWith(".jsonl")) {
      return text
        .split("\n")
        .filter((l) => l.trim())
        .map(safeJSONParse)
        .filter(Boolean);
    }
    const parsed = safeJSONParse(text);
    if (Array.isArray(parsed)) return parsed;
    if (parsed && Array.isArray(parsed.nodes)) return parsed.nodes;
  }
  return [];
}

// ---- internal helpers ----

async function sha256Hex(bytes) {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(buf));
}

function bytesToHex(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) {
    s += u8[i].toString(16).padStart(2, "0");
  }
  return s;
}

function normalizeHash(h) {
  if (!h) return "";
  // Accept "sha256:abc..." or bare hex; strip algorithm prefix + lowercase.
  const stripped = String(h).replace(/^sha256:/i, "").trim().toLowerCase();
  return stripped;
}

/**
 * Return a flat [{path, expected}, ...] regardless of whether the manifest
 * is {files: [...]}, {entries: [...]}, or a bare {path: hash} map.
 */
function normalizeManifestFiles(manifest) {
  if (!manifest) return [];
  if (Array.isArray(manifest.files)) {
    return manifest.files.map((f) => ({
      path: f.path || f.name || "",
      expected: f.sha256 || f.hash || f.digest || "",
    }));
  }
  if (Array.isArray(manifest.entries)) {
    return manifest.entries.map((f) => ({
      path: f.path || f.name || "",
      expected: f.sha256 || f.hash || f.digest || "",
    }));
  }
  // Fallback: treat manifest as {path: hash} map.
  return Object.entries(manifest)
    .filter(([, v]) => typeof v === "string")
    .map(([path, expected]) => ({ path, expected }));
}

function safeJSONParse(s) {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}
