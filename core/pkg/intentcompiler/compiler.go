// Package intentcompiler transforms IntentTickets and raw task descriptions
// into enriched PlanSpec DAGs ready for effect graph evaluation.
//
// The compiler sits between the Intent Studio (which captures user constraints)
// and the Guardian (which evaluates policy). It decomposes plans into atomic
// effects, assigns sandbox profiles, and attaches truth discipline annotations.
package intentcompiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/intent"
)

// CompileRequest is the input to the compiler.
type CompileRequest struct {
	// RawSteps is a list of task descriptions to decompose into steps.
	// Each entry becomes one or more PlanStep nodes.
	RawSteps []string

	// Ticket is the compiled IntentTicket from the Intent Studio.
	// Used to propagate constraints and derive policy requirements.
	Ticket *intent.IntentTicket

	// Envelope bounds the plan. Used for risk/profile decisions.
	Envelope *contracts.AutonomyEnvelope

	// PlanName is an optional human-readable name for the plan.
	PlanName string
}

// CompileResult is the output of the compiler.
type CompileResult struct {
	// Plan is the compiled PlanSpec with a fully-formed DAG.
	Plan *contracts.PlanSpec

	// Warnings are non-fatal issues discovered during compilation.
	Warnings []string
}

// Compiler transforms raw plans into enriched PlanSpec DAGs.
type Compiler struct {
	decomposer *StaticDecomposer
	profiler   *SandboxProfiler
	validator  *GraphValidator
	catalog    *contracts.EffectTypeCatalog
	clock      func() time.Time
}

// NewCompiler creates a compiler with the default effect catalog.
func NewCompiler() *Compiler {
	catalog := contracts.DefaultEffectCatalog()
	return &Compiler{
		decomposer: NewStaticDecomposer(),
		profiler:   NewSandboxProfiler(),
		validator:  NewGraphValidator(catalog),
		catalog:    catalog,
		clock:      time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (c *Compiler) WithClock(clock func() time.Time) *Compiler {
	c.clock = clock
	return c
}

// Compile transforms a CompileRequest into a PlanSpec with a DAG.
func (c *Compiler) Compile(req *CompileRequest) (*CompileResult, error) {
	if len(req.RawSteps) == 0 {
		return nil, fmt.Errorf("no steps to compile")
	}

	c.decomposer.ResetCounter()

	var allSteps []contracts.PlanStep
	var allEdges []contracts.Edge
	var warnings []string

	// Phase 1: Decompose each raw step into PlanStep nodes.
	for _, raw := range req.RawSteps {
		steps, edges, err := c.decomposer.Decompose(raw)
		if err != nil {
			return nil, fmt.Errorf("decompose %q: %w", raw, err)
		}
		allSteps = append(allSteps, steps...)
		allEdges = append(allEdges, edges...)
	}

	// Phase 2: Assign sandbox profiles based on risk class.
	for i := range allSteps {
		backend, profile := c.profiler.AssignProfile(&allSteps[i])
		allSteps[i].RequestedBackend = backend
		allSteps[i].RequestedProfile = profile
	}

	// Phase 3: Propagate constraints from IntentTicket.
	policyConstraints := c.extractPolicyConstraints(req.Ticket)

	// Phase 4: Attach truth annotations.
	truth := c.buildTruthAnnotation(req, allSteps)

	// Phase 5: Build PlanSpec.
	entryPoints := findEntryPoints(allSteps, allEdges)
	exitPoints := findExitPoints(allSteps, allEdges)

	plan := &contracts.PlanSpec{
		ID:        fmt.Sprintf("plan-%d", c.clock().UnixNano()),
		Version:   "2.0.0",
		Name:      req.PlanName,
		CreatedAt: c.clock(),
		DAG: &contracts.DAG{
			Nodes:       allSteps,
			Edges:       allEdges,
			EntryPoints: entryPoints,
			ExitPoints:  exitPoints,
		},
		PolicyConstraints: policyConstraints,
		Truth:             truth,
	}

	// Phase 6: Compute deterministic hash.
	hash, err := computePlanHash(plan)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("failed to compute plan hash: %v", err))
	} else {
		plan.Hash = hash
	}

	// Phase 7: Validate.
	validationErrs := c.validator.Validate(plan)
	for _, ve := range validationErrs {
		warnings = append(warnings, ve.Error())
	}

	return &CompileResult{
		Plan:     plan,
		Warnings: warnings,
	}, nil
}

// extractPolicyConstraints derives PolicyConstraints from an IntentTicket.
func (c *Compiler) extractPolicyConstraints(ticket *intent.IntentTicket) *contracts.PolicyConstraints {
	if ticket == nil {
		return nil
	}

	pc := &contracts.PolicyConstraints{}

	if ticket.Constraints.Risk != nil {
		pc.RequiredApprovals = ticket.Constraints.Risk.RequireApproval
	}

	if ticket.Constraints.Timeline != nil && ticket.Constraints.Timeline.Deadline != nil {
		remaining := time.Until(*ticket.Constraints.Timeline.Deadline)
		if remaining > 0 {
			pc.TimeoutSeconds = int(remaining.Seconds())
		}
	}

	return pc
}

// buildTruthAnnotation creates plan-level truth metadata.
func (c *Compiler) buildTruthAnnotation(req *CompileRequest, steps []contracts.PlanStep) *contracts.TruthAnnotation {
	ta := &contracts.TruthAnnotation{
		Confidence: 1.0, // Start high, reduce based on unknowns.
	}

	// Collect assumptions from ticket.
	if req.Ticket != nil {
		if req.Ticket.Constraints.Risk != nil && !req.Ticket.Constraints.Risk.AllowIrreversible {
			ta.Assumptions = append(ta.Assumptions, "Irreversible effects are prohibited by intent")
		}
		if len(req.Ticket.Constraints.Prohibitions) > 0 {
			for _, p := range req.Ticket.Constraints.Prohibitions {
				ta.Assumptions = append(ta.Assumptions, fmt.Sprintf("Prohibited: %s", p))
			}
		}
	}

	// Collect unknowns from steps.
	for _, step := range steps {
		ta.Unknowns = append(ta.Unknowns, step.Unknowns...)
		ta.Assumptions = append(ta.Assumptions, step.Assumptions...)
	}

	// Reduce confidence for each blocking unknown.
	blockingCount := 0
	for _, u := range ta.Unknowns {
		if u.Impact == contracts.UnknownImpactBlocking {
			blockingCount++
		}
	}
	if blockingCount > 0 {
		ta.Confidence = ta.Confidence * (1.0 - float64(blockingCount)*0.2)
		if ta.Confidence < 0.1 {
			ta.Confidence = 0.1
		}
	}

	return ta
}

// findEntryPoints returns node IDs that have no incoming edges.
func findEntryPoints(steps []contracts.PlanStep, edges []contracts.Edge) []string {
	hasIncoming := make(map[string]bool)
	for _, e := range edges {
		hasIncoming[e.To] = true
	}
	var entries []string
	for _, s := range steps {
		if !hasIncoming[s.ID] {
			entries = append(entries, s.ID)
		}
	}
	return entries
}

// findExitPoints returns node IDs that have no outgoing edges.
func findExitPoints(steps []contracts.PlanStep, edges []contracts.Edge) []string {
	hasOutgoing := make(map[string]bool)
	for _, e := range edges {
		hasOutgoing[e.From] = true
	}
	var exits []string
	for _, s := range steps {
		if !hasOutgoing[s.ID] {
			exits = append(exits, s.ID)
		}
	}
	return exits
}

// computePlanHash creates a deterministic SHA-256 hash of the plan using JCS.
func computePlanHash(plan *contracts.PlanSpec) (string, error) {
	// Hash the DAG only (not the hash field itself).
	hashable := struct {
		ID   string         `json:"id"`
		Name string         `json:"name,omitempty"`
		DAG  *contracts.DAG `json:"dag"`
	}{
		ID:   plan.ID,
		Name: plan.Name,
		DAG:  plan.DAG,
	}

	data, err := canonicalize.JCS(hashable)
	if err != nil {
		return "", fmt.Errorf("JCS canonicalize: %w", err)
	}

	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
