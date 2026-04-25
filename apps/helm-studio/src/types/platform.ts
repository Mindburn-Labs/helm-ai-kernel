export type Edition = 'oss' | 'teams' | 'enterprise'
export type DeploymentMode = 'local' | 'managed' | 'sovereign'
export type AccountLifecycle = 'trial' | 'active' | 'suspended' | 'cancelled'

export type Capability =
  | 'surface.home'
  | 'surface.chat'
  | 'surface.studio'
  | 'surface.ops'
  | 'surface.inbox'
  | 'surface.proof'
  | 'surface.packs'
  | 'surface.connectors'
  | 'surface.settings'
  | 'surface.policy'
  | 'surface.audit'
  | 'surface.identity'
  | 'surface.trust_registry'
  | 'surface.compliance'
  | 'surface.vendor_mesh'
  | 'surface.tenant_admin'
  | 'surface.retention'
  | 'surface.metering'
  | 'workspace.create'
  | 'pack.install'
  | 'evidence.export'
  | 'connectors.custom'
  | 'deployment.sovereign'

export interface Entitlement {
  capability: Capability | string
  limit: number
  current_usage: number
  source: 'edition' | 'trial' | 'deployment' | 'override' | 'migration' | string
  expires_at?: string
}

export interface PlatformSession {
  session_id?: string
  principal_id: string
  tenant_id: string
  workspace_id?: string
  edition: Edition
  deployment_mode: DeploymentMode
  account_lifecycle: AccountLifecycle
  offer_code: string
  entitlements: Entitlement[]
  created_at: string
  last_seen_at: string
  expires_at: string
  device_fingerprint?: string
  signer_id?: string
}

export interface WorkspaceSummary {
  id: string
  name: string
  slug: string
  edition: Edition
  offer_code: string
}

export interface WorkspaceMember {
  user_id: string
  email: string
  role: string
  joined_at: string
}

export interface PlatformBootstrap {
  session: PlatformSession
  workspaces: WorkspaceSummary[]
  snapshot?: unknown
}

export interface BootstrapStatus {
  tenant_id: string
  workspace_id?: string
  project_id?: string
  environment_id?: string
  edition: Edition
  offer_code: string
  account_lifecycle: AccountLifecycle
  status: string
  failure_reason?: string
  created_at: string
  completed_at?: string
  trial_expires_at?: string
  trial_expired?: boolean
}

export type PackChannel = 'core' | 'community' | 'teams' | 'enterprise'
export type PackExtensionPoint = 'route' | 'panel' | 'connector' | 'job' | 'setting' | 'policy' | 'docs'

export interface PackPermission {
  id: string
  justification: string
}

export interface PackSecret {
  name: string
  description: string
  required: boolean
}

export interface PackCheck {
  id: string
  description: string
  command?: string
}

export interface PackSignature {
  signer_id: string
  key_id?: string
  algorithm: string
  signed_at: string
  signature: string
}

export interface PackManifest {
  pack_id: string
  name: string
  version: string
  channel: PackChannel
  summary?: string
  description?: string
  minimum_edition: Edition
  extension_points?: PackExtensionPoint[]
  dependencies?: string[]
  permissions?: PackPermission[]
  secrets?: PackSecret[]
  migrations?: PackCheck[]
  install_checks?: PackCheck[]
  smoke_tests?: PackCheck[]
  rollback_checks?: PackCheck[]
  docs?: string[]
  signatures?: PackSignature[]
}

export interface PackSummary {
  id: string
  name: string
  version: string
  author: string
  category: string
  channel: PackChannel | string
  description: string
  verified: boolean
  installed: boolean
  downloads: number
  signatureValid: boolean
  updatedAt: string
  manifest_hash?: string
  minimum_edition?: Edition
  status?: string
  installed_at?: string
  receipt_id?: string
}

export interface InstalledPack {
  pack_id: string
  version: string
  status: string
  installed_at?: string
}

export interface PackInstallPlan {
  pack_id: string
  version: string
  action?: string
  dry_run: boolean
  eligible: boolean
  requires_upgrade?: boolean
  minimum_edition?: Edition
  current_version?: string
  steps: string[]
  missing_capabilities?: string[]
  missing_secrets?: string[]
}

export interface PackVerification {
  pack_id: string
  verified: boolean
  verification_mode: string
  signer_id?: string
  algorithm: string
  manifest_hash: string
  checks: string[]
  minimum_edition: Edition
  installation_ready: boolean
}

export interface PackReceipt {
  pack_id: string
  action: string
  receipt: {
    receipt_id: string
    pack_name: string
    pack_version: string
    pack_hash: string
    tenant_id: string
    installed_by: string
    installed_at: string
    prev_receipt_id?: string
    content_hash: string
  }
}

export interface PackDetail {
  pack: PackSummary
  manifest: PackManifest
  installed_pack?: InstalledPack | null
  latest_receipt?: PackReceipt | null
}

export interface PackPlanResponse extends PackDetail {
  plan: PackInstallPlan
}

export interface PackActionResult extends PackPlanResponse {
  action: string
  verification: PackVerification
  receipt?: PackReceipt | null
}

export interface Incident {
  id: string
  tenant_id: string
  title: string
  description: string
  severity: string
  state: string
  is_drill: boolean
  detected_at: string
  acked_at?: string
  resolved_at?: string
}

export interface EffectPlanItem {
  effect_type: string
  target: string
  target_type?: string
  cost_cents?: number
  impact?: 'read' | 'modify' | 'delete' | 'create'
}

export interface BlastRadiusResource {
  resource_id: string
  resource_type: string
  effect_type: string
  impact: string
}

export interface BlastRadiusReport {
  plan_id: string
  computed_at?: string
  effect_count: number
  max_risk_taxon: string
  estimated_cost_cents: number
  reversibility_profile: string
  required_approval_level: string
  requires_full_evidence_bundle?: boolean
  requires_two_phase?: boolean
  risk_score: number
  human_summary: string
  affected_resources?: BlastRadiusResource[]
}

export interface OpsPlan {
  id: string
  tenant_id: string
  submitted_by: string
  submitted_at: string
  status: string
  effects: EffectPlanItem[]
  blast_radius?: BlastRadiusReport | null
  approval_required?: boolean
  approved_by?: string
  approved_at?: string
  committed_at?: string
}

export interface BillingOffer {
  id: string
  edition: Edition
  offer_code: string
  name: string
  limits: Record<string, number>
  features: string[]
  price_monthly_cents: number
  created_at: string
}

export interface UsageSummary {
  tenant_id: string
  period: string
  counters: Record<string, number>
  reason_codes: Record<string, number>
  budget_used_cents: number
  budget_limit_cents: number
  last_updated: string
}

export interface BudgetStatus {
  tenant_id: string
  status: string
  budget_used_cents: number
  budget_limit_cents: number
  percent_used: number
  alert_type?: string
  alert_counter?: string
  alert_current?: number
  alert_limit?: number
}

export interface PublicReceiptVerification {
  receipt: {
    id: string
    action: string
    actor: string
    timestamp: string
    hash: string
    epoch: number
    signatureValid: boolean
  }
}

export interface PublicEvidenceBundle {
  valid: boolean
  evidence: {
    id: string
    title: string
    status: string
    hash: string
    created_at: string
  }
}

export interface PublicApprovalStatus {
  id: string
  title: string
  status: string
}

const ROUTE_CAPABILITIES: Record<string, Capability> = {
  '/policy': 'surface.policy',
  '/audit': 'surface.audit',
  '/identity': 'surface.identity',
  '/trust-registry': 'surface.trust_registry',
  '/compliance': 'surface.compliance',
  '/vendor-mesh': 'surface.vendor_mesh',
  '/tenant-admin': 'surface.tenant_admin',
  '/retention': 'surface.retention',
  '/metering': 'surface.metering',
}

export function hasCapability(entitlements: Entitlement[], capability: Capability | string): boolean {
  return entitlements.some((entitlement) => entitlement.capability === capability)
}

export function canAccessRoute(entitlements: Entitlement[], route: string): boolean {
  const capability = ROUTE_CAPABILITIES[route]
  if (!capability) return true
  return hasCapability(entitlements, capability)
}

export function defaultEntitlements(edition: Edition, deploymentMode: DeploymentMode, lifecycle: AccountLifecycle): Entitlement[] {
  const entitlements: Entitlement[] = [
    'surface.home',
    'surface.chat',
    'surface.studio',
    'surface.ops',
    'surface.inbox',
    'surface.proof',
    'surface.packs',
    'surface.connectors',
    'surface.settings',
    'workspace.create',
    'pack.install',
  ].map((capability) => ({
    capability,
    limit: -1,
    current_usage: 0,
    source: 'edition',
  }))

  if (edition === 'teams' || edition === 'enterprise' || lifecycle === 'trial') {
    entitlements.push(
      { capability: 'evidence.export', limit: -1, current_usage: 0, source: 'edition' },
    )
  }

  if (edition === 'enterprise' || lifecycle === 'trial') {
    const source = lifecycle === 'trial' && edition !== 'enterprise' ? 'trial' : 'edition'
    for (const capability of Object.values(ROUTE_CAPABILITIES)) {
      entitlements.push({ capability, limit: -1, current_usage: 0, source })
    }
    entitlements.push({ capability: 'connectors.custom', limit: -1, current_usage: 0, source })
  }

  if (deploymentMode === 'sovereign') {
    entitlements.push(
      { capability: 'deployment.sovereign', limit: -1, current_usage: 0, source: 'deployment' },
      { capability: 'connectors.custom', limit: -1, current_usage: 0, source: 'deployment' },
    )
  }

  return dedupeEntitlements(entitlements)
}

export const defaultPlatformSession: PlatformSession = {
  principal_id: 'local-preview',
  tenant_id: 'local-preview',
  workspace_id: 'local-preview',
  edition: 'enterprise',
  deployment_mode: 'managed',
  account_lifecycle: 'active',
  offer_code: 'enterprise-custom',
  entitlements: defaultEntitlements('enterprise', 'managed', 'active'),
  created_at: new Date(0).toISOString(),
  last_seen_at: new Date(0).toISOString(),
  expires_at: new Date(8640000000000000).toISOString(),
}

export function legacyAuthSessionToPlatformSession(session: {
  principal_id?: string
  tenant_id?: string
  created_at?: string
  last_seen_at?: string
  expires_at?: string
  device_fingerprint?: string
  signer_id?: string
}): PlatformSession {
  const tenantId = session.tenant_id ?? session.principal_id ?? 'local-preview'
  return {
    ...defaultPlatformSession,
    principal_id: session.principal_id ?? tenantId,
    tenant_id: tenantId,
    workspace_id: tenantId,
    created_at: session.created_at ?? defaultPlatformSession.created_at,
    last_seen_at: session.last_seen_at ?? defaultPlatformSession.last_seen_at,
    expires_at: session.expires_at ?? defaultPlatformSession.expires_at,
    device_fingerprint: session.device_fingerprint,
    signer_id: session.signer_id,
  }
}

function dedupeEntitlements(entitlements: Entitlement[]): Entitlement[] {
  const seen = new Map<string, Entitlement>()
  for (const entitlement of entitlements) {
    seen.set(entitlement.capability, entitlement)
  }
  return [...seen.values()]
}
