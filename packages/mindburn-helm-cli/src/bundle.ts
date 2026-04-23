// ─── HELM Bundle Acquisition ─────────────────────────────────────────────────
// GitHub release resolution, download, attestation verification, content-addressable cache.

import { createHash } from "node:crypto";
import {
    createReadStream,
    createWriteStream,
    existsSync,
    mkdirSync,
    readdirSync,
    readFileSync,
    writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { pipeline } from "node:stream/promises";

import { computeManifestRootHash, sha256Hex, verifyAttestationSignature } from "./crypto.js";
import type { Attestation } from "./types.js";

// ─── Constants ───────────────────────────────────────────────────────────────

const GITHUB_API = "https://api.github.com/repos/Mindburn-Labs/helm/releases/latest";
const DEFAULT_CACHE_DIR = join(homedir(), ".helm", "cache");

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ReleaseInfo {
    tag: string;
    bundleUrl: string | null;
    attestationUrl: string | null;
    signatureUrl: string | null;
    htmlUrl: string;
}

export interface DownloadProgress {
    phase: "downloading" | "extracting" | "verifying";
    bytesDownloaded: number;
    totalBytes: number | null;
}

// ─── Release Resolution ──────────────────────────────────────────────────────

/**
 * Resolve the latest GitHub release and find evidence bundle assets.
 */
export async function resolveLatestRelease(): Promise<ReleaseInfo | null> {
    try {
        const response = await fetch(GITHUB_API, {
            headers: {
                Accept: "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        });

        if (!response.ok) return null;

        const release = (await response.json()) as {
            tag_name: string;
            html_url: string;
            assets: Array<{ name: string; browser_download_url: string }>;
        };

        const bundleAsset = release.assets.find((a) =>
            a.name.match(/^helm-evidence.*\.tar\.gz$/),
        );
        const attestationAsset = release.assets.find((a) =>
            a.name.match(/^helm-attestation.*\.json$/),
        );
        const signatureAsset = release.assets.find((a) =>
            a.name.match(/^helm-attestation.*\.sig$/),
        );

        return {
            tag: release.tag_name,
            bundleUrl: bundleAsset?.browser_download_url ?? null,
            attestationUrl: attestationAsset?.browser_download_url ?? null,
            signatureUrl: signatureAsset?.browser_download_url ?? null,
            htmlUrl: release.html_url,
        };
    } catch {
        return null;
    }
}

// ─── Cache Management ────────────────────────────────────────────────────────

/**
 * Get the cache directory path.
 */
export function getCacheDir(customDir?: string): string {
    return customDir ?? DEFAULT_CACHE_DIR;
}

/**
 * Ensure the cache directory exists.
 */
export function ensureCacheDir(customDir?: string): void {
    const dir = getCacheDir(customDir);
    mkdirSync(dir, { recursive: true });
}

/**
 * Check if a bundle is already cached by its manifest root hash.
 */
export function getCachedBundle(manifestRootHash: string, customDir?: string): string | null {
    const cacheDir = getCacheDir(customDir);
    const prefix = manifestRootHash.substring(0, 16);

    try {
        const entries = readdirSync(cacheDir);
        const match = entries.find((e) => e.startsWith(prefix));
        if (match) {
            const bundlePath = join(cacheDir, match);
            const indexPath = join(bundlePath, "00_INDEX.json");
            if (existsSync(indexPath)) return bundlePath;
        }
    } catch {
        // Cache doesn't exist yet
    }

    return null;
}

// ─── Download & Verify ───────────────────────────────────────────────────────

/**
 * Download an evidence bundle from a URL.
 * If attestation + signature URLs are provided, verify authenticity.
 *
 * @returns Path to extracted bundle in cache.
 */
export async function downloadBundle(
    bundleUrl: string,
    options: {
        attestationUrl?: string | null;
        signatureUrl?: string | null;
        noCache?: boolean;
        cacheDir?: string;
        onProgress?: (progress: DownloadProgress) => void;
    } = {},
): Promise<string> {
    const { onProgress } = options;

    // 1. Download bundle tarball
    onProgress?.({ phase: "downloading", bytesDownloaded: 0, totalBytes: null });

    const response = await fetch(bundleUrl, { redirect: "follow" });
    if (!response.ok || !response.body) {
        throw new Error(`Download failed: HTTP ${response.status}`);
    }

    const totalBytes = response.headers.get("content-length")
        ? Number(response.headers.get("content-length"))
        : null;

    const chunks: Buffer[] = [];
    let bytesDownloaded = 0;
    const reader = response.body.getReader();

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = Buffer.from(value);
        chunks.push(chunk);
        bytesDownloaded += chunk.length;
        onProgress?.({ phase: "downloading", bytesDownloaded, totalBytes });
    }

    const tarball = Buffer.concat(chunks);
    const tarballHash = sha256Hex(tarball);

    // 2. Verify attestation if available
    if (options.attestationUrl) {
        onProgress?.({ phase: "verifying", bytesDownloaded, totalBytes });

        const attestation = await fetchAttestation(
            options.attestationUrl,
            options.signatureUrl ?? null,
            tarballHash,
        );

        if (!attestation.verified) {
            throw new Error(`Attestation verification failed: ${attestation.reason}`);
        }
    }

    // 3. Extract to temp location
    onProgress?.({ phase: "extracting", bytesDownloaded, totalBytes });

    const tempDir = join(getCacheDir(options.cacheDir), `_tmp_${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });

    const tarPath = join(tempDir, "bundle.tar.gz");
    writeFileSync(tarPath, tarball);

    // Extract using tar (universally available on macOS/Linux)
    const { execSync } = await import("node:child_process");
    execSync(`tar -xzf "${tarPath}" -C "${tempDir}"`, { stdio: "pipe" });

    // Find the extracted bundle root (look for 00_INDEX.json)
    const extractedRoot = findBundleRoot(tempDir);
    if (!extractedRoot) {
        throw new Error("Extracted archive does not contain a valid evidence bundle (no 00_INDEX.json found)");
    }

    // 4. Move to content-addressable cache
    const indexData = readFileSync(join(extractedRoot, "00_INDEX.json"));
    const manifestRoot = computeManifestRootHash(indexData);
    const cacheKey = manifestRoot.substring(0, 16);
    const finalPath = join(getCacheDir(options.cacheDir), cacheKey);

    if (!existsSync(finalPath) || options.noCache) {
        const { renameSync } = await import("node:fs");
        try {
            renameSync(extractedRoot, finalPath);
        } catch {
            // Cross-device rename — fallback to copy
            execSync(`cp -r "${extractedRoot}" "${finalPath}"`, { stdio: "pipe" });
        }
    }

    // Cleanup temp
    execSync(`rm -rf "${tempDir}"`, { stdio: "pipe" });

    onProgress?.({ phase: "verifying", bytesDownloaded, totalBytes });

    return finalPath;
}

// ─── Attestation Fetching ────────────────────────────────────────────────────

async function fetchAttestation(
    attestationUrl: string,
    signatureUrl: string | null,
    expectedAssetSha256: string,
): Promise<{ verified: boolean; reason?: string; attestation?: Attestation }> {
    try {
        const response = await fetch(attestationUrl, { redirect: "follow" });
        if (!response.ok) {
            return { verified: false, reason: `attestation fetch failed: HTTP ${response.status}` };
        }

        const attestationJson = await response.text();
        const attestation = JSON.parse(attestationJson) as Attestation;

        // Check asset hash
        if (attestation.asset_sha256 !== expectedAssetSha256) {
            return {
                verified: false,
                reason: `asset sha256 mismatch: expected ${attestation.asset_sha256.substring(0, 16)}…, got ${expectedAssetSha256.substring(0, 16)}…`,
            };
        }

        // Verify signature if available
        if (signatureUrl) {
            const sigResponse = await fetch(signatureUrl, { redirect: "follow" });
            if (sigResponse.ok) {
                const signatureBase64 = (await sigResponse.text()).trim();
                const result = verifyAttestationSignature(attestationJson, signatureBase64);

                if (!result.verified) {
                    return { verified: false, reason: "Ed25519 signature verification failed" };
                }
            }
        }

        return { verified: true, attestation };
    } catch (err) {
        return {
            verified: false,
            reason: `attestation verification error: ${err instanceof Error ? err.message : String(err)}`,
        };
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Recursively find the directory containing 00_INDEX.json.
 */
function findBundleRoot(dir: string): string | null {
    if (existsSync(join(dir, "00_INDEX.json"))) return dir;

    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
        if (entry.isDirectory()) {
            const result = findBundleRoot(join(dir, entry.name));
            if (result) return result;
        }
    }

    return null;
}
