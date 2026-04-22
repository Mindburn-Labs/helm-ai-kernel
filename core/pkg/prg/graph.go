package prg

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	pkg_artifact "github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
)

// LogicOperator defines how requirements are combined.
type LogicOperator string

const (
	AND LogicOperator = "AND"
	OR  LogicOperator = "OR"
	NOT LogicOperator = "NOT"
)

// Requirement defines a logic condition.
// For Node 8 (PRG), we upgrade this to support both legacy artifact checks AND CEL.
type Requirement struct {
	ID          string `json:"id"`
	Description string `json:"description"`

	// Legacy Artifact Check (Optional shortcut)
	ArtifactType string `json:"artifact_type,omitempty"`
	SignerID     string `json:"signer_id,omitempty"`

	// CEL Expression (The Node 8 core feature)
	// Input: "intent", "state", "artifacts" (list of artifacts)
	Expression string `json:"expression,omitempty"`
}

// RequirementSet is a recursive logic tree.
type RequirementSet struct {
	ID           string           `json:"id"`
	Logic        LogicOperator    `json:"logic"`
	Requirements []Requirement    `json:"requirements"`
	Children     []RequirementSet `json:"children"`
}

// ExecutionGraph is the compiled representation.
type ExecutionGraph struct {
	RootNode *Node
}

type Node struct {
	Operator LogicOperator
	Expr     string // CEL expression
	Subs     []*Node

	// Pre-compiled checks (logic-less optimization)
	Req Requirement
}

// Hash computes a deterministic hash.
func (rs *RequirementSet) Hash() string {
	// Simplified recursive hash
	content := fmt.Sprintf("id=%s:logic=%s:", rs.ID, rs.Logic)
	for _, req := range rs.Requirements {
		content += fmt.Sprintf("req=%s:%s:%s;", req.ID, req.ArtifactType, req.Expression)
	}
	for _, child := range rs.Children {
		content += "child=" + child.Hash() + ";"
	}
	return fmt.Sprintf("hash:%x", content)
}

// Graph maps an ActionID to its RequirementSet (Policy).
type Graph struct {
	Rules map[string]RequirementSet
}

func NewGraph() *Graph {
	return &Graph{
		Rules: make(map[string]RequirementSet),
	}
}

// ContentHash computes a content-addressed hash of the entire policy graph.
// GOV-001: Used by Guardian to tie DecisionRecords to exact policy state.
func (g *Graph) ContentHash() (string, error) {
	if len(g.Rules) == 0 {
		return "", nil
	}
	// Sort rule keys for determinism
	keys := make([]string, 0, len(g.Rules))
	for k := range g.Rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	content := ""
	for _, k := range keys {
		rs := g.Rules[k]
		content += k + "=" + rs.Hash() + ";"
	}
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:]), nil
}

// BindByCapability explicitly binds a policy to a verified capability ID (GAP-05).
func (g *Graph) BindByCapability(capabilityID string, set RequirementSet) error {
	// For now, we reuse the Rules map where key is the resource/action identifier.
	// In the future, we might have a separate map for Capabilities vs standard Actions.
	g.Rules[capabilityID] = set
	return nil
}

func (g *Graph) AddRule(actionID string, set RequirementSet) error {
	g.Rules[actionID] = set
	return nil
}

// Legacy Validate stub (to satisfy existing code if any).
// Real validation happens via Evaluator.
// Validate checks if the artifacts satisfy the requirements for the action.
func (g *Graph) Validate(actionID string, artifacts []*pkg_artifact.ArtifactEnvelope) (bool, string, error) {
	rule, exists := g.Rules[actionID]
	if !exists {
		// Default Deny if no rule, or maybe Allow if implied?
		// For high security, explicit allow is better.
		// checks if action is "known" but has no reqs?
		return false, "", fmt.Errorf("no policy defined for action %s", actionID)
	}

	if check(rule, artifacts) {
		return true, rule.Hash(), nil
	}
	return false, "", fmt.Errorf("missing requirement")
}

//nolint:gocognit // recursive requirement checking is inherently complex
func check(rs RequirementSet, artifacts []*pkg_artifact.ArtifactEnvelope) bool {
	// Recursive check
	if len(rs.Requirements) == 0 && len(rs.Children) == 0 {
		return true // Empty set = pass
	}

	// Check Leaves (direct requirements)
	leafResults := []bool{}
	for _, req := range rs.Requirements {
		has := false
		// Simple Artifact Type check for now (Node 3 style)
		if req.ArtifactType != "" {
			for _, art := range artifacts {
				if art.Type == req.ArtifactType {
					has = true
					break
				}
			}
		} else {
			// Expression or others ignored in this legacy check
			has = true
		}
		leafResults = append(leafResults, has)
	}

	// Check Children (recursive)
	for _, child := range rs.Children {
		childResult := check(child, artifacts)
		leafResults = append(leafResults, childResult)
	}

	// Apply logic operator to all results
	if len(leafResults) == 0 {
		return true
	}

	switch rs.Logic {
	case AND:
		for _, r := range leafResults {
			if !r {
				return false
			}
		}
		return true
	case OR:
		for _, r := range leafResults {
			if r {
				return true
			}
		}
		return false
	default:
		// Unknown logic, fail safe
		return false
	}
}
