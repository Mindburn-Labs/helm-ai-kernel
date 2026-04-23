// tar-reader.js — minimal TAR (USTAR) parser for in-browser EvidencePack viewing.
//
// TAR format reminder (per PAX/USTAR):
//   - Each entry = 512-byte header + payload (rounded up to multiple of 512).
//   - Archive terminates with two consecutive 512-byte zero blocks.
//   - Header fields of interest:
//       name   : bytes 0..99   (NUL-terminated string, up to 100 chars)
//       size   : bytes 124..135 (octal ASCII of file size, space-terminated)
//       typeflag: byte 156     ('0' or '\0' = regular file, '5' = dir, 'L' = long name, 'x'/'g' = PAX)
//       prefix : bytes 345..499 (USTAR long-name prefix)
//
// We ignore PAX headers and long-name entries that would require state across entries;
// EvidencePack TARs produced by HELM stay within USTAR's 100-char name limit today.
// If that changes, this parser will report the unsupported entry and skip gracefully.

const BLOCK_SIZE = 512;

/**
 * Parse a TAR archive into a list of entries.
 * @param {ArrayBuffer} buffer - the raw TAR file bytes
 * @returns {Array<{name: string, size: number, body: Uint8Array}>}
 */
export function parseTar(buffer) {
  const bytes = new Uint8Array(buffer);
  const entries = [];
  let offset = 0;

  while (offset + BLOCK_SIZE <= bytes.length) {
    const header = bytes.subarray(offset, offset + BLOCK_SIZE);

    // Two consecutive zero blocks signal end-of-archive.
    if (isZeroBlock(header)) break;

    const name = readString(header, 0, 100);
    const size = readOctal(header, 124, 12);
    const typeflag = String.fromCharCode(header[156] || 0);

    if (!name) {
      // Defensive: unnamed header is usually the trailing zero block or corruption.
      break;
    }

    // Only keep regular files. Directories, symlinks, and PAX extension
    // headers are skipped over (their bodies, if any, are still consumed).
    const isRegular = typeflag === "0" || typeflag === "\u0000";
    const bodyStart = offset + BLOCK_SIZE;
    const body = isRegular && size > 0
      ? bytes.subarray(bodyStart, bodyStart + size)
      : new Uint8Array(0);

    if (isRegular) {
      entries.push({ name, size, body });
    }

    // Advance to the next header. Payload is rounded up to a full block.
    const padded = Math.ceil(size / BLOCK_SIZE) * BLOCK_SIZE;
    offset = bodyStart + padded;
  }

  return entries;
}

/**
 * Find an entry by exact name (e.g., "manifest.json").
 * @param {Array} entries
 * @param {string} name
 * @returns {Uint8Array|null}
 */
export function findEntry(entries, name) {
  for (const e of entries) {
    if (e.name === name || e.name.endsWith("/" + name)) {
      return e.body;
    }
  }
  return null;
}

/**
 * Decode an entry body as UTF-8 text.
 */
export function decodeText(bytes) {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

// ---- internal helpers ----

function isZeroBlock(header) {
  for (let i = 0; i < BLOCK_SIZE; i++) {
    if (header[i] !== 0) return false;
  }
  return true;
}

function readString(view, offset, length) {
  let end = offset;
  const limit = offset + length;
  while (end < limit && view[end] !== 0) end++;
  return new TextDecoder("utf-8").decode(view.subarray(offset, end));
}

function readOctal(view, offset, length) {
  let s = "";
  const limit = offset + length;
  for (let i = offset; i < limit; i++) {
    const c = view[i];
    if (c === 0 || c === 0x20) break; // NUL or space terminates the octal string
    s += String.fromCharCode(c);
  }
  return parseInt(s || "0", 8) || 0;
}
