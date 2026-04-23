// ─── HELM Cryptographic Primitives ───────────────────────────────────────────
// Ed25519 signature verification, Merkle tree, manifest root hash.
// Zero native deps — uses Node crypto stdlib.

import { createHash, verify as cryptoVerify } from "node:crypto";

// ─── Pinned Public Keys ─────────────────────────────────────────────────────
// Key rotation: new keys are appended, old keys remain for back-compat.
// The CLI selects the latest key by default for newly signed attestations.
// Verification tries all keys in order until one matches.

export const PINNED_PUBLIC_KEYS: readonly { id: string; key: string; since: string }[] = [
    {
        id: "helm-release-2026-v1",
        // Ed25519 public key in PEM format.
        // Generated via: openssl genpkey -algorithm Ed25519 -out private.pem
        //                openssl pkey -in private.pem -pubout -out public.pem
        key: [
            "-----BEGIN PUBLIC KEY-----",
            "MCowBQYDK2VwAyEAPlaceholderKeyForGenerationDuringFirstRelease00=",
            "-----END PUBLIC KEY-----",
        ].join("\n"),
        since: "2026-02-21",
    },
];

// ─── Manifest Root Hash ─────────────────────────────────────────────────────

/**
 * Compute the manifest root hash: sha256(canonical_bytes(00_INDEX.json)).
 * This is the identity of the bundle and the cache key.
 */
export function computeManifestRootHash(indexJsonBytes: Buffer): string {
    return sha256Hex(indexJsonBytes);
}

// ─── Merkle Tree ─────────────────────────────────────────────────────────────
// Merkle tree construction:
// - Leaves sorted by path ascending
// - leaf_hash = sha256(0x00 || entry_sha256_bytes)
// - parent = sha256(0x01 || left || right)
// - If odd leaves, duplicate last

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

/**
 * Compute the Merkle root over a list of entry hashes.
 * @param entryHashes - Array of { path, sha256_hex } sorted by path ascending.
 * @returns Merkle root as hex string.
 */
export function computeMerkleRoot(
    entryHashes: ReadonlyArray<{ path: string; sha256: string }>,
): string {
    if (entryHashes.length === 0) {
        // Empty tree: hash of empty buffer
        return sha256Hex(Buffer.alloc(0));
    }

    // Sort by path ascending (defensive — caller should pre-sort)
    const sorted = [...entryHashes].sort((a, b) => a.path.localeCompare(b.path));

    // Compute leaf hashes: sha256(0x00 || sha256_bytes)
    let level: Buffer[] = sorted.map((entry) => {
        const hashBytes = Buffer.from(entry.sha256, "hex");
        return sha256Raw(Buffer.concat([LEAF_PREFIX, hashBytes]));
    });

    // Build tree bottom-up
    while (level.length > 1) {
        const next: Buffer[] = [];
        for (let i = 0; i < level.length; i += 2) {
            const left = level[i];
            // If odd number of nodes, duplicate the last
            const right = i + 1 < level.length ? level[i + 1] : level[i];
            next.push(sha256Raw(Buffer.concat([NODE_PREFIX, left, right])));
        }
        level = next;
    }

    return level[0].toString("hex");
}

// ─── Ed25519 Signature Verification ──────────────────────────────────────────

/**
 * Verify an Ed25519 signature over data using pinned public keys.
 * @returns true if any pinned key verifies the signature.
 */
export function verifyEd25519(
    data: Buffer,
    signatureBase64: string,
): { verified: boolean; keyId?: string } {
    const signature = Buffer.from(signatureBase64, "base64");

    for (const pinnedKey of PINNED_PUBLIC_KEYS) {
        try {
            const valid = cryptoVerify(null, data, pinnedKey.key, signature);
            if (valid) {
                return { verified: true, keyId: pinnedKey.id };
            }
        } catch {
            // Key format mismatch or algorithm issue — try next key
            continue;
        }
    }

    return { verified: false };
}

/**
 * Verify an attestation: check Ed25519 signature over sha256(canonical_bytes).
 * @param attestationJson - Canonical JSON string of the attestation.
 * @param signatureBase64 - Base64-encoded Ed25519 signature.
 */
export function verifyAttestationSignature(
    attestationJson: string,
    signatureBase64: string,
): { verified: boolean; keyId?: string } {
    const data = sha256Raw(Buffer.from(attestationJson, "utf-8"));
    return verifyEd25519(data, signatureBase64);
}

// ─── Hash Utilities ──────────────────────────────────────────────────────────

export function sha256Hex(data: Buffer): string {
    return createHash("sha256").update(data).digest("hex");
}

export function sha256Raw(data: Buffer): Buffer {
    return createHash("sha256").update(data).digest();
}

/**
 * Canonicalize a JSON object: stable key ordering, no trailing whitespace.
 * Matches JCS (RFC 8785) for interop with Go's canonicalize.JCS().
 */
export function canonicalJSON(obj: unknown): string {
    return JSON.stringify(sortKeys(obj));
}

function sortKeys(value: unknown): unknown {
    if (value === null || typeof value !== "object") return value;
    if (Array.isArray(value)) return value.map(sortKeys);
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
        sorted[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return sorted;
}
