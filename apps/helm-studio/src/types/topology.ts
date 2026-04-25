/**
 * Platform Topology Types (§4).
 *
 * Canonical topology layers: Account → Tenant → Organization → Environment → Workspace → Scope → Object
 * All switching, inheritance, and deep-linking resolves through these types.
 */

// ── §4.1 Canonical Topology Layers ──────────────────

export interface Account {
  id: string
  name: string
  email: string
  tenantIds: string[]
  locale: string
  timezone: string
  mfaEnabled: boolean
  passkeysEnabled: boolean
}

export interface Tenant {
  id: string
  name: string
  slug: string
  profile: 'teams' | 'enterprise' | 'sovereign'
  organizationIds: string[]
  ssoEnabled: boolean
  scimEnabled: boolean
  retentionDays: number
  jurisdictionDefault: string
  billingStatus: 'active' | 'trial' | 'suspended'
}

export interface Organization {
  id: string
  tenantId: string
  name: string
  environmentIds: string[]
  genomeHash: string | null
  genomeEpoch: number
}

export interface Environment {
  id: string
  organizationId: string
  name: string
  type: 'production' | 'staging' | 'sandbox' | 'recovery' | 'jurisdiction'
  isActive: boolean
}

export interface Workspace {
  id: string
  name: string
  tenantId: string
  environmentId: string
  userId: string
  pinnedOrgIds: string[]
  primaryOrgId: string
  pinnedScopeIds: string[]
  activeThreadId: string | null
  lensDefaults: Record<string, string>
  layoutState: Record<string, unknown>
  lastAccessed: string
}

export interface Scope {
  id: string
  organizationId: string
  parentScopeId: string | null
  name: string
  type: 'department' | 'legal_entity' | 'committee' | 'program' | 'business_line' | 'region' | 'custom'
  depth: number
  childScopeIds: string[]
  localPolicyIds: string[]
  localBudgetIds: string[]
  localConnectorIds: string[]
}

// ── §4.2 Object Reference ───────────────────────────

export interface ObjectRef {
  id: string
  type: string
  tenantId: string
  organizationId: string
  scopeId?: string
  environmentId?: string
}

// ── §4.3 Inheritance Chain ──────────────────────────

export type InheritanceLayer = 'tenant' | 'organization' | 'scope' | 'object'

/** Resolve configs by walking up the inheritance chain */
export function resolveInheritance<T>(
  chain: Partial<Record<InheritanceLayer, T>>,
): T | undefined {
  return chain.object ?? chain.scope ?? chain.organization ?? chain.tenant
}

// ── §4.4 Switching Context ──────────────────────────

export interface SwitchContext {
  tenantId: string
  organizationId: string
  environmentId: string
  workspaceId: string
  scopeId?: string
}

/**
 * Build a canonical deep link from a switch context.
 */
export function buildContextUrl(ctx: SwitchContext, surface: string, objectId?: string): string {
  const base = `/app/${ctx.tenantId}/${ctx.environmentId}/${surface}`
  return objectId ? `${base}/${objectId}` : base
}
