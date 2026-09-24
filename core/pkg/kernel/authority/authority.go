// Package authority is the kernel's pure authority function (target
// architecture §4.1 and §4.5, rules R3 and R7).
//
// Decide(input, snapshot) performs no I/O, reads no clock and draws no
// randomness: authority time is an Input field, and policy is a Snapshot that
// Compile builds once, when a policy version is activated. Replaying a
// decision means calling Decide again with the stored Input and a Snapshot
// with the same digest.
//
// Every failure is a DENY: an unknown action, a missing snapshot, a missing
// authority time, a condition that fails to compile, an evaluation error
// (including a missing attribute), a non-boolean result, or a condition that
// exhausts its cost budget.
package authority

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/cel-go/cel"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policycel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

// CostLimit bounds the runtime cost of one CEL condition, in cel-go cost
// units. A condition that exceeds it is denied instead of running for as long
// as caller-sized input makes it run (audit E-09). There is deliberately no
// wall-clock deadline: a deadline would make the verdict depend on machine
// speed, and the same input could then decide differently on replay.
const CostLimit uint64 = 100_000

// Profile names the evaluation semantics a snapshot digest pins. Changing the
// CEL environment, the cost limit or the combination rules must change it.
var Profile = fmt.Sprintf("helm.authority.cel.v1;cost_limit=%d", CostLimit)

// Reserved input keys. Decide writes them itself, so attributes cannot
// substitute the action being authorized or the authority time.
const (
	KeyAction    = "action"
	KeyTimestamp = "timestamp"
)

// Input is everything Decide may consult besides the snapshot.
type Input struct {
	// Action selects the rule to apply.
	Action string `json:"action"`
	// Attributes become the CEL `input` document. Decide evaluates their JSON
	// form, so a stored Input replays exactly as it was decided live.
	Attributes map[string]any `json:"attributes,omitempty"`
	// Time is the authority time. It is exposed to conditions as
	// input.timestamp (Unix seconds).
	Time time.Time `json:"time"`
}

// Decision is the result of Decide. Its fields are comparable across runs, so
// a replay can assert that it reproduces a stored decision exactly.
type Decision struct {
	Verdict    contracts.Verdict    `json:"verdict"`
	ReasonCode contracts.ReasonCode `json:"reason_code,omitempty"`
	// Unmet names the requirements that evaluated to false. It is set only
	// for MISSING_REQUIREMENT.
	Unmet []string `json:"unmet,omitempty"`
	// RuleHash is the content hash of the rule that was applied.
	RuleHash       string `json:"rule_hash,omitempty"`
	SnapshotDigest string `json:"snapshot_digest"`
	// Detail explains an evaluation failure. It can name policy internals, so
	// callers log it rather than return it to the requester.
	Detail string `json:"detail,omitempty"`
}

// Snapshot is a compiled, immutable policy version. It is safe for concurrent
// use.
type Snapshot struct {
	digest string
	rules  map[string]rule
}

// Digest pins the policy content and the evaluation profile.
func (s *Snapshot) Digest() string {
	if s == nil {
		return ""
	}
	return s.digest
}

type rule struct {
	hash       string
	root       node
	readsInput bool  // false for an unconditional rule, which needs no input document
	err        error // the rule failed to compile; its action is denied
}

type node struct {
	id       string
	logic    prg.LogicOperator
	leaves   []leaf
	children []node
}

type leaf struct {
	id           string
	program      cel.Program // nil for an artifact-presence leaf
	artifactType string
}

// Compile builds the snapshot for a policy graph. A rule that cannot be
// compiled stays in the snapshot and denies its action; the returned error
// lists every such rule so activation can refuse the policy version.
func Compile(g *prg.Graph) (*Snapshot, error) {
	if g == nil {
		g = prg.NewGraph()
	}
	contentHash, err := g.ContentHash()
	if err != nil {
		return nil, fmt.Errorf("authority: hash policy graph: %w", err)
	}
	env, err := newEnv()
	if err != nil {
		return nil, fmt.Errorf("authority: create CEL environment: %w", err)
	}

	sum := sha256.Sum256([]byte(Profile + "\n" + contentHash))
	s := &Snapshot{
		digest: "sha256:" + hex.EncodeToString(sum[:]),
		rules:  make(map[string]rule, len(g.Rules)),
	}
	actions := make([]string, 0, len(g.Rules))
	for action := range g.Rules {
		actions = append(actions, action)
	}
	sort.Strings(actions)

	var errs []error
	for _, action := range actions {
		set := g.Rules[action]
		root, err := compileSet(env, set)
		if err != nil {
			err = fmt.Errorf("action %s: %w", action, err)
			errs = append(errs, err)
		}
		s.rules[action] = rule{hash: set.Hash(), root: root, readsInput: root.hasLeaves(), err: err}
	}
	return s, errors.Join(errs...)
}

func newEnv() (*cel.Env, error) {
	opts := []cel.EnvOption{cel.Variable("input", cel.MapType(cel.StringType, cel.DynType))}
	return cel.NewEnv(append(opts, policycel.TaintEnvOptions()...)...)
}

func compileSet(env *cel.Env, set prg.RequirementSet) (node, error) {
	n := node{id: set.ID, logic: set.Logic}
	switch set.Logic {
	case prg.AND, prg.OR, prg.NOT, "":
	default:
		return n, fmt.Errorf("requirement set %s: unknown logic operator %q", set.ID, set.Logic)
	}
	for _, req := range set.Requirements {
		switch {
		case req.Expression != "":
			expression := policycel.RewritePRGTaintContains(req.Expression)
			ast, issues := env.Compile(expression)
			if issues != nil && issues.Err() != nil {
				return n, fmt.Errorf("requirement %s: compile: %w", req.ID, issues.Err())
			}
			program, err := env.Program(ast, cel.CostLimit(CostLimit))
			if err != nil {
				return n, fmt.Errorf("requirement %s: program: %w", req.ID, err)
			}
			n.leaves = append(n.leaves, leaf{id: req.ID, program: program})
		case req.ArtifactType != "":
			n.leaves = append(n.leaves, leaf{id: req.ID, artifactType: req.ArtifactType})
		default:
			// A requirement with no condition is undefined, not satisfied.
			return n, fmt.Errorf("requirement %s has neither an expression nor an artifact_type", req.ID)
		}
	}
	for _, child := range set.Children {
		c, err := compileSet(env, child)
		if err != nil {
			return n, err
		}
		n.children = append(n.children, c)
	}
	return n, nil
}

// Decide applies the snapshot's rule for in.Action to in.
func Decide(in Input, s *Snapshot) Decision {
	if s == nil {
		return deny(Decision{}, contracts.ReasonPRGEvalError, "no compiled policy snapshot")
	}
	d := Decision{SnapshotDigest: s.digest}
	r, ok := s.rules[in.Action]
	if !ok {
		return deny(d, contracts.ReasonNoPolicy, "")
	}
	d.RuleHash = r.hash
	if r.err != nil {
		return deny(d, contracts.ReasonPRGEvalError, r.err.Error())
	}
	if in.Time.IsZero() {
		return deny(d, contracts.ReasonPRGEvalError, "authority time is required")
	}
	// An unconditional rule reads no input, so it needs no document.
	var activation map[string]any
	var artifacts any
	if r.readsInput {
		doc, err := document(in)
		if err != nil {
			return deny(d, contracts.ReasonPRGEvalError, err.Error())
		}
		activation = map[string]any{"input": doc, "taint": doc["taint"]}
		artifacts = doc["artifacts"]
	}
	satisfied, unmet, err := r.root.eval(activation, artifacts)
	if err != nil {
		return deny(d, contracts.ReasonPRGEvalError, err.Error())
	}
	if !satisfied {
		d.Unmet = unmet
		return deny(d, contracts.ReasonMissingRequirement, "")
	}
	d.Verdict = contracts.VerdictAllow
	return d
}

func deny(d Decision, code contracts.ReasonCode, detail string) Decision {
	d.Verdict = contracts.VerdictDeny
	d.ReasonCode = code
	d.Detail = detail
	return d
}

// document returns the JSON form of the attributes with the reserved keys
// set, so live evaluation sees exactly what a stored Input decodes to.
func document(in Input) (map[string]any, error) {
	raw, err := json.Marshal(in.Attributes)
	if err != nil {
		return nil, fmt.Errorf("encode attributes: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode attributes: %w", err)
	}
	if doc == nil {
		doc = make(map[string]any, 2)
	}
	doc[KeyAction] = in.Action
	doc[KeyTimestamp] = in.Time.Unix()
	return doc, nil
}

func (n node) hasLeaves() bool {
	if len(n.leaves) > 0 {
		return true
	}
	for _, child := range n.children {
		if child.hasLeaves() {
			return true
		}
	}
	return false
}

// eval evaluates every leaf and child before combining them, so an error
// anywhere in the rule denies regardless of the other results.
func (n node) eval(activation map[string]any, artifacts any) (bool, []string, error) {
	if len(n.leaves) == 0 && len(n.children) == 0 {
		return true, nil, nil
	}
	results := make([]bool, 0, len(n.leaves)+len(n.children))
	var unmet []string
	for _, l := range n.leaves {
		ok, err := l.eval(activation, artifacts)
		if err != nil {
			return false, nil, err
		}
		results = append(results, ok)
		if !ok {
			unmet = append(unmet, l.id)
		}
	}
	for _, child := range n.children {
		ok, childUnmet, err := child.eval(activation, artifacts)
		if err != nil {
			return false, nil, err
		}
		results = append(results, ok)
		if !ok {
			unmet = append(unmet, childUnmet...)
		}
	}

	if combine(n.logic, results) {
		return true, nil, nil
	}
	if n.logic == prg.NOT {
		return false, []string{n.id}, nil
	}
	return false, unmet, nil
}

func (l leaf) eval(activation map[string]any, artifacts any) (bool, error) {
	if l.program == nil {
		return hasArtifact(artifacts, l.artifactType), nil
	}
	out, _, err := l.program.Eval(activation)
	if err != nil {
		return false, fmt.Errorf("requirement %s: %w", l.id, err)
	}
	value, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("requirement %s: result is %s, not bool", l.id, out.Type().TypeName())
	}
	return value, nil
}

// combine applies a logic operator. NOT is satisfied unless every result is.
func combine(logic prg.LogicOperator, results []bool) bool {
	every, some := true, false
	for _, r := range results {
		every = every && r
		some = some || r
	}
	switch logic {
	case prg.OR:
		return some
	case prg.NOT:
		return !every
	default: // AND or empty; other operators were rejected by Compile
		return every
	}
}

func hasArtifact(artifacts any, artifactType string) bool {
	list, _ := artifacts.([]any)
	for _, item := range list {
		if envelope, ok := item.(map[string]any); ok && envelope["type"] == artifactType {
			return true
		}
	}
	return false
}
