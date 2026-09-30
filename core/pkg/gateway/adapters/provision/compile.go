package provision

import (
	"errors"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

// Compiled is a plan ready to apply: the parsed plan with each mandate node's
// terms in the form the database stores, and each node's limits.
type Compiled struct {
	Plan *effectargs.Plan
	// Nodes are the plan's mandate nodes, in the plan's order.
	Nodes []Node
}

// Node is one mandate node of a compiled plan.
type Node struct {
	Name   string
	Holder string
	// Parent is the node above, empty for the root.
	Parent string
	// Depth is 0 for the root.
	Depth  int
	Terms  authorityrows.Terms
	Limits []authorityrows.LimitSpec
}

// Check parses and compiles the arguments of an authority plan effect. It is
// the pure part of Propose (admission calls it after effectargs.Validate) and
// of Dispatch. Every error is a *adapters.Refusal.
func Check(effectType string, raw []byte) (*Compiled, error) {
	plan, err := effectargs.ParsePlan(effectType, raw)
	if err != nil {
		return nil, adapters.Refuse(contracts.ReasonSchemaViolation, "%v", err)
	}
	return Compile(plan)
}

// Compile turns a parsed plan into what Apply writes, and refuses a plan that
// cannot apply whatever the database holds: terms the store would refuse (a
// condition that does not compile), a child wider than its parent, a limit
// above the same limit higher up. It is pure, so Propose runs it before an
// approver is asked. Every error is a *adapters.Refusal.
func Compile(plan *effectargs.Plan) (*Compiled, error) {
	c := &Compiled{Plan: plan, Nodes: make([]Node, len(plan.Mandates))}
	index := make(map[string]int, len(plan.Mandates))
	for i, m := range plan.Mandates {
		index[m.Node] = i
	}
	for i, m := range plan.Mandates {
		terms, err := storeTerms(m.Terms, plan)
		if err != nil {
			return nil, adapters.Refuse(contracts.ReasonSchemaViolation, "mandate %q: %v", m.Node, err)
		}
		depth := 0
		for at := m.Parent; at != ""; at = plan.Mandates[index[at]].Parent {
			if depth++; depth > len(plan.Mandates) {
				return nil, adapters.Refuse(contracts.ReasonSchemaViolation, "mandate %q is in a cycle", m.Node)
			}
		}
		c.Nodes[i] = Node{Name: m.Node, Holder: m.Holder, Parent: m.Parent, Depth: depth, Terms: terms}
	}
	for _, l := range plan.Limits {
		spec := authorityrows.LimitSpec{Unit: l.Unit, Measure: l.Measure, Window: l.Window, Value: l.Value, Span: l.Span}
		if err := spec.Validate(); err != nil {
			return nil, adapters.Refuse(contracts.ReasonSchemaViolation, "limit on %q: %v", l.Node, err)
		}
		i := index[l.Node]
		c.Nodes[i].Limits = append(c.Nodes[i].Limits, spec)
	}
	for i := range c.Nodes {
		n := &c.Nodes[i]
		if n.Parent == "" {
			continue
		}
		if err := n.Terms.Within(c.Nodes[index[n.Parent]].Terms); err != nil {
			return nil, adapters.Refuse(contracts.ReasonDelegationScopeViolation, "mandate %q is wider than its parent %q: %v", n.Name, n.Parent, err)
		}
		for _, l := range n.Limits {
			if ceiling, ok := ancestorCeiling(c, index, n, l); ok && l.Value > ceiling {
				return nil, adapters.Refuse(contracts.ReasonDelegationScopeViolation,
					"mandate %q limits %s at %d, above the %d of an ancestor", n.Name, l.Unit, l.Value, ceiling)
			}
		}
	}
	return c, nil
}

// ancestorCeiling is the lowest limit of the same unit, measure, window and
// span on any mandate above n.
func ancestorCeiling(c *Compiled, index map[string]int, n *Node, want authorityrows.LimitSpec) (int64, bool) {
	var ceiling int64
	found := false
	for parent := n.Parent; parent != ""; parent = c.Nodes[index[parent]].Parent {
		for _, l := range c.Nodes[index[parent]].Limits {
			if limitKey(l) == limitKey(want) && (!found || l.Value < ceiling) {
				ceiling, found = l.Value, true
			}
		}
	}
	return ceiling, found
}

// storeTerms is a plan node's terms as the store keeps them: normalized, in the
// plan's validity window.
func storeTerms(t effectargs.PlanTerms, plan *effectargs.Plan) (authorityrows.Terms, error) {
	terms := authorityrows.Terms{
		EffectTypes:       t.EffectTypes,
		Targets:           t.Targets,
		PerCallLimit:      t.PerCallLimit,
		ApprovalThreshold: t.ApprovalThreshold,
		ValidFrom:         plan.ValidFrom,
		ValidUntil:        plan.ValidUntil,
		Condition:         t.Condition,
		ApprovalRequired:  t.ApprovalRequired,
	}
	if len(t.RiskClasses) > 0 {
		terms.RiskClasses = make(map[string]mandates.RiskClass, len(t.RiskClasses))
		for name, class := range t.RiskClasses {
			terms.RiskClasses[name] = mandates.RiskClass(class)
		}
	}
	return authorityrows.NormalizeTerms(terms)
}

// limitKey is what makes two limits of one mandate the same limit.
type limitID struct {
	unit, measure, window string
	span                  int
}

func limitKey(l authorityrows.LimitSpec) limitID {
	return limitID{l.Unit, l.Measure, l.Window, l.Span}
}

// refusalOf is the *adapters.Refusal inside err, if any.
func refusalOf(err error) (*adapters.Refusal, bool) {
	var r *adapters.Refusal
	if errors.As(err, &r) {
		return r, true
	}
	return nil, false
}
