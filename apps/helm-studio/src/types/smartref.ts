// ═══════════════════════════════════════════════════════════════
// SmartRef — Canonical DTO for the Evidence UX layer
// All identity, evidence, and provenance rendering derives from this.
// Backend-owned, never minted client-side.
// ═══════════════════════════════════════════════════════════════

export type EvidenceState =
  | 'DRAFT'
  | 'GOVERNED'
  | 'RECEIPTED'
  | 'VERIFIED'
  | 'ATTESTED'
  | 'REDACTED'
  | 'DRIFT'
  | 'QUARANTINED'

export type RefKind =
  | 'ORG'
  | 'GENOME'
  | 'PATCH'
  | 'INTENT'
  | 'DECISION'
  | 'RUN'
  | 'POLICY'
  | 'PROOF_NODE'
  | 'TRUST_EVENT'
  | 'PACK'
  | 'CONNECTOR'
  | 'EXPORT'
  | 'ALERT'

export type TruthDensity = 'NORMAL' | 'OPERATOR' | 'AUDITOR'

export type EvidenceTab = 'SUMMARY' | 'EVIDENCE' | 'TECHNICAL'

export type RedactionProfile = 'OPERATOR' | 'AUDITOR' | 'REGULATOR' | 'PUBLIC'

export interface SmartRef {
  kind: RefKind

  // ── Human surface ──
  title: string                    // "Deploy to production"
  subtitle?: string                // "Payments - Stripe connector"
  handle: string                   // "run-deploy-prod-7K3D"
  status?: string                  // "Denied", "Active", "Running", "Paused"
  evidence_state: EvidenceState[]

  // ── Deterministic identity anchors ──
  canonical_hash: string           // "sha256:..."
  fingerprint_seed: string         // stable seed derived from canonical_hash

  // ── Causality and ordering ──
  epoch?: number                   // genome epoch
  lamport?: number                 // ordering height
  parents?: SmartRefParent[]

  // ── Redaction (optional, shown in Technical tab) ──
  redaction?: SmartRefRedaction

  // ── Deep link ──
  href: string                     // "/runs/run-deploy-prod-7K3D"
}

export interface SmartRefParent {
  kind: RefKind
  handle: string
  canonical_hash: string
  fingerprint_seed: string
  title: string
}

export interface SmartRefRedaction {
  profile_required?: RedactionProfile
  reason_code?: string
  payload_hash?: string
  ciphertext_hash?: string
  blob_ref?: string
  kek_ref?: string
  key_policy_hash?: string
  legal_hold?: boolean
  shredded?: boolean
}

// ─── Utility: build a minimal SmartRef from hash-based data ───
// Used when the backend returns raw fields instead of a full SmartRef.
export function toSmartRef(opts: {
  kind: RefKind
  title: string
  hash: string
  handle?: string
  status?: string
  evidence_state?: EvidenceState[]
  epoch?: number
  lamport?: number
}): SmartRef {
  const shortcode = opts.hash.replace(/^sha256:/, '').slice(0, 4).toUpperCase()
  const slug = opts.title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 24)
  const kindPrefix = opts.kind.toLowerCase().slice(0, 3)

  return {
    kind: opts.kind,
    title: opts.title,
    subtitle: undefined,
    handle: opts.handle || `${kindPrefix}-${slug}-${shortcode}`,
    status: opts.status,
    evidence_state: opts.evidence_state || ['DRAFT'],
    canonical_hash: opts.hash,
    fingerprint_seed: opts.hash.replace(/^sha256:/, '').slice(0, 16),
    epoch: opts.epoch,
    lamport: opts.lamport,
    href: `/${opts.kind.toLowerCase()}s/${opts.handle || `${kindPrefix}-${slug}-${shortcode}`}`,
  }
}
