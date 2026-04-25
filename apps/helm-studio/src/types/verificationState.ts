/**
 * Verification state model for pack registry.
 *
 * Defines the lifecycle states a pack goes through from unsigned
 * through full HELM verification. Used by both OSS verify and
 * platform UI to render verification badges and control transitions.
 */

export type VerificationState =
  | 'unsigned'
  | 'signed'
  | 'verified'
  | 'verified_by_helm'
  | 'revoked'

export interface VerificationTransition {
  from: VerificationState
  to: VerificationState
  requiresConformance: boolean
  requiresSignature: boolean
}

/** Valid state transitions for pack verification. */
export const VERIFICATION_TRANSITIONS: VerificationTransition[] = [
  { from: 'unsigned', to: 'signed', requiresConformance: false, requiresSignature: true },
  { from: 'signed', to: 'verified', requiresConformance: true, requiresSignature: true },
  { from: 'verified', to: 'verified_by_helm', requiresConformance: true, requiresSignature: true },
  { from: 'unsigned', to: 'revoked', requiresConformance: false, requiresSignature: false },
  { from: 'signed', to: 'revoked', requiresConformance: false, requiresSignature: false },
  { from: 'verified', to: 'revoked', requiresConformance: false, requiresSignature: false },
  { from: 'verified_by_helm', to: 'revoked', requiresConformance: false, requiresSignature: false },
]

/** Check if a transition between two states is valid. */
export function isValidTransition(from: VerificationState, to: VerificationState): boolean {
  return VERIFICATION_TRANSITIONS.some((t) => t.from === from && t.to === to)
}

/** Get the badge display info for a verification state. */
export function getVerificationBadge(state: VerificationState): {
  label: string
  color: string
  icon: string
} {
  switch (state) {
    case 'unsigned':
      return { label: 'Unsigned', color: 'gray', icon: 'circle-dashed' }
    case 'signed':
      return { label: 'Signed', color: 'blue', icon: 'pen-tool' }
    case 'verified':
      return { label: 'Verified', color: 'green', icon: 'shield-check' }
    case 'verified_by_helm':
      return { label: 'Verified by HELM', color: 'purple', icon: 'badge-check' }
    case 'revoked':
      return { label: 'Revoked', color: 'red', icon: 'shield-x' }
  }
}

/** Whether a state qualifies for badge issuance. */
export function isBadgeEligible(state: VerificationState): boolean {
  return state === 'verified' || state === 'verified_by_helm'
}
