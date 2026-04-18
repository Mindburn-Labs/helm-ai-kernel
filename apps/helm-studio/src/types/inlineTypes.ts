// ═══════════════════════════════════════════════════════════════
// Inline UX Primitives — Type Contracts
//
// Canonical types for the Mama AI inline component layer.
// These drive chips, changeset cards, gate requests, forms,
// validation banners, and the command surface.
// ═══════════════════════════════════════════════════════════════

// ── §1 Inline Reference System ──────────────────────────────────

/** Canonical node type families used for chip coloring */
export type NodeFamily =
  | 'org'       // OrgUnit, Team, Role
  | 'identity'  // Person, Agent, Committee
  | 'ai'        // Agent, Tool, Connector
  | 'infra'     // Service, DataDomain, Corridor
  | 'gov'       // Policy, Gate, Budget, Control, Obligation
  | 'legal'     // LegalEntity, Contract, Jurisdiction
  | 'ops'       // Incident, Run, Change, Release
  | 'meta'      // Evidence, EvidencePack, Audit

/** Node chip: inline @Type: Label mention */
export interface NodeChipData {
  canonicalId: string
  nodeType: string
  family: NodeFamily
  label: string
  state?: string           // Active, Draft, Archived, etc.
  parentLabel?: string     // For breadcrumb context
}

/** Canonical verb list for edge chips */
export type EdgeVerb =
  | 'owns'
  | 'manages'
  | 'reports_to'
  | 'uses'
  | 'governs'
  | 'enforces'
  | 'approves'
  | 'funds'
  | 'audits'
  | 'connects'
  | 'depends_on'
  | 'blocked_by'
  | 'delegates_to'
  | 'monitors'
  | 'classifies'
  | 'produces'
  | 'consumes'

/** Edge chip: inline verb -> @Type: Label mention */
export interface EdgeChipData {
  verb: EdgeVerb
  sourceId: string
  targetId: string
  sourceLabel: string
  targetLabel: string
  sourceType: string
  targetType: string
}

/** Verifier status for artifact chips */
export type VerifierStatus = 'Attested' | 'Partial' | 'Rejected' | 'Pending'

/** Artifact chip: inline #Evidence: or #Doc: mention */
export interface ArtifactChipData {
  artifactHash: string
  filename: string
  verifierStatus: VerifierStatus
  contentType?: string
  size?: number
}

/** Scope context for per-message scope override */
export interface ScopeContext {
  entityType: string       // 'LegalEntity', 'OrgUnit', 'Team', etc.
  entityId: string
  label: string
  inherited: boolean       // true = inherited from current subcanvas
}

/** Union of all chip data for inline rendering */
export type InlineChipData = NodeChipData | EdgeChipData | ArtifactChipData

// ── §2 ChangeSet Pipeline ───────────────────────────────────────

export type ChangeOpKind = 'create' | 'update' | 'delete'

export interface NodeOp {
  kind: ChangeOpKind
  nodeType: string
  canonicalId: string
  label: string
  /** Only for updates: field-level diffs */
  diffs?: FieldDiff[]
}

export interface EdgeOp {
  kind: ChangeOpKind
  verb: EdgeVerb
  sourceId: string
  targetId: string
  sourceLabel: string
  targetLabel: string
}

export interface FieldDiff {
  field: string
  oldValue: string | number | boolean | null
  newValue: string | number | boolean | null
  /** True if this field affects policy enforcement */
  binding: boolean
}

export type RiskTier = 'low' | 'medium' | 'high' | 'critical'

export interface ChangeSetData {
  changeSetId: string
  summary: string
  nodeOps: NodeOp[]
  edgeOps: EdgeOp[]
  requiredGates: string[]
  riskTier: RiskTier
  evidenceImpacts: string[]
  validation: ValidationResult
  committed: boolean
  commitTimestamp?: string
}

export interface Violation {
  code: string
  message: string
  severity: 'error' | 'warning'
  nodeId?: string
  field?: string
}

export interface FixSuggestion {
  label: string
  description: string
  /** Auto-apply action identifier */
  actionId: string
}

export interface ValidationResult {
  passed: boolean
  violations: Violation[]
  suggestions: FixSuggestion[]
}

// ── §3 Approvals, Gates & Exceptions ────────────────────────────

export interface GateRequestData {
  gateId: string
  subject: string
  reason: string
  quorumRequired: number
  quorumCurrent: number
  deadlineIso?: string
  slaHours?: number
  requiredEvidence: string[]
  eligiblePrincipals: string[]
  currentUserEligible: boolean
  committeeLabel?: string
}

export interface ExceptionDraftData {
  exceptionId: string
  /** What policy/rule is being overridden */
  overriddenPolicyId: string
  overriddenPolicyLabel: string
  /** Scope diff: what changes */
  scopeDiff: FieldDiff[]
  /** Default: 14 days from now */
  expiryIso: string
  /** Required compensating controls */
  compensatingControls: string[]
  /** True if this targets a P0 ceiling (requires extra approval) */
  targetsPZeroCeiling: boolean
}

// ── §4 Subsystem Embeds ─────────────────────────────────────────

export interface PolicyTraceData {
  blockedBy: string         // Policy label
  policyId: string
  conflictInfo?: string     // e.g., "P1 vs P2, deny-wins"
  fixSuggestion: string
}

export interface EvidenceCoverageData {
  controlsSatisfied: number
  controlsMissing: number
  evidencePacksAttached: number
  evidencePacksMissing: number
}

// ── §5 Configuration Forms ──────────────────────────────────────

export type FormNodeType =
  | 'LegalEntity'
  | 'Contract'
  | 'DataDomain'
  | 'Control'
  | 'Risk'
  | 'Budget'

export interface FormFieldDef {
  key: string
  label: string
  type: 'text' | 'number' | 'select' | 'date' | 'toggle'
  required: boolean
  advanced: boolean
  options?: string[]
  defaultValue?: string | number | boolean
  placeholder?: string
}

export interface TypedFormSchema {
  nodeType: FormNodeType
  title: string
  fields: FormFieldDef[]
}

// ── §6 Command Surface ─────────────────────────────────────────

export type SlashCommandType =
  | 'create'
  | 'bind'
  | 'simulate'
  | 'open'
  | 'export'
  | 'apply'
  | 'rollback'

export interface SlashCommand {
  type: SlashCommandType
  raw: string
  args: string[]
  scope?: ScopeContext
}

// ── §7 Context Control ─────────────────────────────────────────

export interface ContextSnapshot {
  activeScope: ScopeContext | null
  referencedNodes: NodeChipData[]
  activePolicies: Array<{ id: string; label: string; tier: string }>
  activeBudgets: Array<{ id: string; label: string; remaining: string }>
  scopeLocked: boolean
  pinnedItems: string[]
}

// ── §9 Observability ────────────────────────────────────────────

export type OperationalStatus =
  | 'Connected' | 'Degraded' | 'Drift'          // Connector
  | 'Healthy' | 'Down'                           // Service
  | 'Open' | 'Contained'                         // Incident
  | 'Running' | 'Denied' | 'Completed' | 'Failed' // Run

export interface LiveStatusData {
  nodeId: string
  nodeType: string
  label: string
  status: OperationalStatus
  updatedAt: string
}

export interface TimelineEvent {
  id: string
  label: string
  timestamp: string
  kind: 'info' | 'warning' | 'error' | 'success'
}

export interface TimelineSnippetData {
  nodeId: string
  nodeType: 'Incident' | 'Audit' | 'Change' | 'Run'
  label: string
  events: TimelineEvent[]
}

// ── §10 Onboarding ──────────────────────────────────────────────

export interface BootstrapRecipe {
  recipeId: string
  title: string
  description: string
  /** What gets created */
  includes: string[]
  /** Always starts as Draft */
  changeSetPreview?: ChangeSetData
}

export interface IndustryPack {
  packId: string
  title: string
  description: string
  /** Default overlay tier */
  tier: 'P0' | 'P1' | 'P2'
  /** True if applying requires gate approval */
  requiresGate: boolean
  tags: string[]
}

// ── Utility: Node family resolver ───────────────────────────────

const NODE_TYPE_TO_FAMILY: Record<string, NodeFamily> = {
  orgunit: 'org', team: 'org', role: 'org',
  person: 'identity', agent: 'ai', committee: 'identity',
  tool: 'ai', connector: 'ai',
  service: 'infra', datadomain: 'infra', corridor: 'infra',
  policy: 'gov', gate: 'gov', budget: 'gov', control: 'gov', obligation: 'gov',
  legalentity: 'legal', contract: 'legal', jurisdiction: 'legal',
  incident: 'ops', run: 'ops', change: 'ops', release: 'ops',
  evidence: 'meta', evidencepack: 'meta', audit: 'meta',
}

/** Resolve a node type string to its family for chip coloring */
export function resolveNodeFamily(nodeType: string): NodeFamily {
  return NODE_TYPE_TO_FAMILY[nodeType.toLowerCase()] ?? 'meta'
}
