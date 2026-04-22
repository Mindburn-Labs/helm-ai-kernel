// ─── HELM Gate & Profile Loader ──────────────────────────────────────────────
// Loads profiles.json — single source of truth.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { ConformanceLevel } from "./types.js";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface LevelDef {
    profile: string;
    gates: readonly string[];
    description: string;
}

export interface ProfileDef {
    id: string;
    description: string;
    required_gates: readonly string[];
    inherits?: string;
    overrides?: Record<string, unknown>;
}

interface ProfilesManifest {
    version: string;
    levels: Record<ConformanceLevel, LevelDef>;
    profiles: Record<string, ProfileDef>;
    gate_names: Record<string, string>;
}

// ─── Load ────────────────────────────────────────────────────────────────────

function loadProfiles(): ProfilesManifest {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const profilesPath = join(__dirname, "profiles.json");
    return JSON.parse(readFileSync(profilesPath, "utf-8")) as ProfilesManifest;
}

const manifest = loadProfiles();

// ─── Exports ─────────────────────────────────────────────────────────────────

export const PROFILES_VERSION: string = manifest.version;
export const LEVELS: Record<ConformanceLevel, LevelDef> = manifest.levels;
export const PROFILES: Record<string, ProfileDef> = manifest.profiles;
export const GATE_NAMES: Record<string, string> = manifest.gate_names;

/**
 * Get the gate IDs required by a conformance level.
 */
export function gatesForLevel(level: ConformanceLevel): readonly string[] {
    return LEVELS[level].gates;
}

/**
 * Get the human-readable name for a gate ID.
 */
export function gateName(gateId: string): string {
    return GATE_NAMES[gateId] ?? gateId;
}
