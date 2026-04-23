package orgdna

import "time"

// ────────────────────────────────────────────────────────────────
// OrgGenome — the declarative organizational genome
// ────────────────────────────────────────────────────────────────

// OrgGenome represents the declarative organizational genome.
// It is the single source of truth for an organization's structure,
// policies, modules, and governance rules.
type OrgGenome struct {
	Meta              GenomeMeta          `json:"meta"`
	Morphogenesis     []MorphogenesisRule `json:"morphogenesis"`
	Regulation        RegulationConfig    `json:"regulation"`
	PhenotypeContract PhenotypeContract   `json:"phenotype_contract"`
	Environment       *EnvironmentProfile `json:"environment,omitempty"`
	Identity          *OrgIdentity        `json:"identity,omitempty"`
	Primitives        *OrgPrimitives      `json:"primitives,omitempty"`
	Modules           []ModuleDeclaration `json:"modules"`
	Provenance        map[string]string   `json:"provenance,omitempty"`
}

// GenomeMeta contains genome identification and lifecycle metadata.
type GenomeMeta struct {
	GenomeID  string    `json:"genome_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	License   string    `json:"license,omitempty"`
}

// ────────────────────────────────────────────────────────────────
// Morphogenesis — conditional structural generation rules
// ────────────────────────────────────────────────────────────────

// MorphogenesisRule defines a conditional structural generation rule.
// When the CEL expression in When evaluates to true, the Generate
// structure is applied to the genome.
type MorphogenesisRule struct {
	ID       string                 `json:"id"`
	When     string                 `json:"when"` // CEL expression
	Generate MorphogenesisGenerator `json:"generate"`
}

// MorphogenesisGenerator specifies what to generate when a rule fires.
type MorphogenesisGenerator struct {
	Modules    []ModuleDeclaration `json:"modules,omitempty"`
	Regulation *RegulationConfig   `json:"regulation,omitempty"`
}

// ────────────────────────────────────────────────────────────────
// Regulation — policy, control loops, essential variables
// ────────────────────────────────────────────────────────────────

// RegulationConfig defines the governance layer of the genome.
type RegulationConfig struct {
	EssentialVariables []EssentialVariable    `json:"essential_variables,omitempty"`
	ControlLoops       []ControlLoop          `json:"control_loops,omitempty"`
	RegulationGraph    *RegulationGraph       `json:"regulation_graph,omitempty"`
	PolicySet          map[string]interface{} `json:"policy_set,omitempty"`
}

// EssentialVariable defines a variable that must stay within bounds
// for the organization to remain viable (Ashby's Law).
type EssentialVariable struct {
	Name         string                  `json:"name"`
	VariableID   string                  `json:"variable_id"`
	Bounds       EssentialVariableBounds `json:"bounds"`
	CurrentValue float64                 `json:"current_value,omitempty"`
}

// EssentialVariableBounds defines the acceptable range for a variable.
type EssentialVariableBounds struct {
	Type string  `json:"type"` // "numeric_range", "boolean"
	Min  float64 `json:"min,omitempty"`
	Max  float64 `json:"max,omitempty"`
}

// ControlLoop defines a feedback control loop for regulation.
type ControlLoop struct {
	LoopID     string             `json:"loop_id"`
	Type       string             `json:"type,omitempty"`       // "pid", "hysteresis"
	Parameters map[string]float64 `json:"parameters,omitempty"` // Kp, Ki, Kd
	Input      string             `json:"input,omitempty"`
	Output     string             `json:"output,omitempty"`
	Expression string             `json:"expression,omitempty"` // CEL expression
}

// RegulationGraph defines a state machine for regulation modes.
type RegulationGraph struct {
	InitialModeID string           `json:"initial_mode_id"`
	Modes         []RegulationMode `json:"modes"`
}

// RegulationMode is a single mode in the regulation state machine.
type RegulationMode struct {
	ModeID string `json:"mode_id"`
}

// PhenotypeContract defines the determinism and output guarantees.
type PhenotypeContract struct {
	MustProduce []string `json:"must_produce"`
	Determinism struct {
		RequiresRandomSeed bool `json:"requires_random_seed"`
	} `json:"determinism"`
}

// EnvironmentProfile defines environment-specific bindings.
type EnvironmentProfile struct {
	ProfileID string                 `json:"profile_id"`
	Bindings  map[string]interface{} `json:"bindings"`
}

// OrgIdentity carries the organization's public name.
type OrgIdentity struct {
	Name string `json:"name"`
}

// ────────────────────────────────────────────────────────────────
// Primitives — Units, Roles, Principals (L1)
// ────────────────────────────────────────────────────────────────

// OrgPrimitives defines the fundamental building blocks of the organization.
type OrgPrimitives struct {
	Units      []OrgUnit   `json:"units,omitempty"`
	Roles      []Role      `json:"roles,omitempty"`
	Principals []Principal `json:"principals,omitempty"`
}

// OrgUnit represents a recursive organizational unit (Department, Team, Pod).
type OrgUnit struct {
	UnitID          string    `json:"unit_id"`
	Name            string    `json:"name"`
	Type            string    `json:"type"` // "team", "division", "squad"
	ParentID        string    `json:"parent_id,omitempty"`
	Children        []OrgUnit `json:"children,omitempty"`
	AssignedRoles   []string  `json:"assigned_roles,omitempty"`
	PolicyRefs      []string  `json:"policy_refs,omitempty"`
	BudgetRef       string    `json:"budget_ref,omitempty"`
	KnowledgeBaseID string    `json:"knowledge_base_id,omitempty"`
}

// Role defines a set of responsibilities and permissions.
type Role struct {
	RoleID             string   `json:"role_id"`
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	Responsibilities   []string `json:"responsibilities"`
	DelegationAllowed  bool     `json:"delegation_allowed"`
	SeparationOfDuties []string `json:"separation_of_duties,omitempty"`
	RequiredTraits     []string `json:"required_traits,omitempty"`
}

// Principal represents an actor that can assume a role.
type Principal struct {
	PrincipalID string            `json:"principal_id"`
	Type        string            `json:"type"` // "human", "agent", "system"
	Name        string            `json:"name"`
	Traits      []string          `json:"traits,omitempty"`
	RiskScore   float64           `json:"risk_score,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ────────────────────────────────────────────────────────────────
// Modules — capability declarations
// ────────────────────────────────────────────────────────────────

// ModuleDeclaration declares a capability module within the genome.
type ModuleDeclaration struct {
	Type         string             `json:"type"`
	Jurisdiction string             `json:"jurisdiction"`
	Version      string             `json:"version"`
	Capabilities []string           `json:"capabilities,omitempty"`
	Attestation  *ModuleAttestation `json:"attestation,omitempty"`
}

// ModuleAttestation provides cryptographic proof of module provenance.
type ModuleAttestation struct {
	SignerID  string `json:"signer_id"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key,omitempty"`
	Digest    string `json:"digest"`
	IssuedAt  string `json:"issued_at,omitempty"`
}

// ────────────────────────────────────────────────────────────────
// OrgPhenotype — the compiled runtime artifact
// ────────────────────────────────────────────────────────────────

// OrgPhenotype represents the compiled runtime artifact produced by
// the OrgDNA compiler. It is the executable organizational state.
type OrgPhenotype struct {
	Metadata            PhenotypeMetadata   `json:"metadata"`
	Primitives          *OrgPrimitives      `json:"primitives,omitempty"`
	ActiveModules       []ModuleDeclaration `json:"active_modules,omitempty"`
	ActiveCapabilities  []string            `json:"active_capabilities,omitempty"`
	RegulationConfig    RegulationConfig    `json:"regulation_config"`
	Environment         *EnvironmentProfile `json:"environment,omitempty"`
	ActivePhenotypeHash string              `json:"active_phenotype_hash"`
	Receipt             *CompilationReceipt `json:"receipt,omitempty"`
}

// PhenotypeMetadata carries provenance information for a compiled phenotype.
type PhenotypeMetadata struct {
	GenomeID      string    `json:"genome_id"`
	SourceHash    string    `json:"source_hash"`
	CompiledAt    time.Time `json:"compiled_at"`
	SchemaVersion string    `json:"schema_version"`
}

// CompilationReceipt is a cryptographic attestation of the compilation process.
type CompilationReceipt struct {
	ReceiptID       string    `json:"receipt_id"`
	GenomeID        string    `json:"genome_id"`
	InputHash       string    `json:"input_hash"`
	OutputHash      string    `json:"output_hash"`
	CompiledAt      time.Time `json:"compiled_at"`
	Signature       string    `json:"signature,omitempty"`
	SignerID        string    `json:"signer_id,omitempty"`
	SignerPublicKey string    `json:"signer_public_key,omitempty"`
}
