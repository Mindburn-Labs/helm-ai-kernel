package effectargs

// quantum_posture: the plan digest is a SHA-256 content digest of the plan's
// canonical form; nothing here signs or verifies, and no post-quantum claim is
// made.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// The authority effects (contract 5, docs/architecture/gateway-provisioning-
// api.md): the plan of an organization's authority, applied behind a
// distinct human's approval (provision) or, when it only narrows, without
// (narrow).
const (
	AuthorityProvision = "helm.authority.provision.v1"
	AuthorityNarrow    = "helm.authority.narrow.v1"
)

// MaxPlanBytes bounds a plan: the effect API's 64 KiB argument cap is for
// every other effect.
const MaxPlanBytes = 524288

// IsAuthorityPlan reports whether effectType is one of the two plan effects.
func IsAuthorityPlan(effectType string) bool {
	return effectType == AuthorityProvision || effectType == AuthorityNarrow
}

// WidensAuthority reports whether effectType is one of the gateway's own
// authority effects (helm.authority.*) that widens, and so needs a distinct
// human's approval with step-up: every one but helm.authority.narrow.v1, which
// only narrows and is admitted without approval.
func WidensAuthority(effectType string) bool {
	return strings.HasPrefix(effectType, "helm.authority.") && effectType != AuthorityNarrow
}

// Plan is a parsed authority plan. Every field is validated against the
// closed schema (protocols/json-schemas/effects/authority/*.v1.json) and the
// rules the schema cannot state; Digest is the plan digest.
type Plan struct {
	// Schema is the plan's schema constant, equal to its effect type.
	Schema      string
	OrgRef      string
	VersionRef  string
	Stage       string
	BaseDigest  string
	ValidFrom   time.Time
	ValidUntil  time.Time
	EffectTypes []PlanEffectType
	Principals  []PlanPrincipal
	// Disable lists the principals the plan disables.
	Disable  []string
	Mandates []PlanMandate
	Limits   []PlanLimit
	// Digest is the lower-case hex SHA-256 of the RFC 8785 form of the plan
	// without base_plan_digest.
	Digest string
}

// PlanEffectType is an effect type the plan registers.
type PlanEffectType struct {
	EffectType string
	RiskClass  string
}

// PlanPrincipal is a principal the plan registers.
type PlanPrincipal struct {
	ID         string
	Kind       string
	EnsureOnly bool
	External   *PlanExternal
}

// PlanExternal is a principal's external subject.
type PlanExternal struct {
	System string
	ID     string
}

// PlanMandate is one mandate node of the plan's tree.
type PlanMandate struct {
	Node   string
	Holder string
	// Parent is the node it is delegated from; empty for the root.
	Parent string
	Terms  PlanTerms
}

// PlanTerms are a mandate's terms as the plan states them.
type PlanTerms struct {
	EffectTypes []string
	// Targets is nil when any target is allowed.
	Targets           []string
	ApprovalRequired  []string
	ApprovalThreshold *int64
	PerCallLimit      *int64
	Condition         string
	RiskClasses       map[string]string
}

// PlanLimit is a limit of a mandate node.
type PlanLimit struct {
	Node    string
	Unit    string
	Measure string
	Window  string
	Value   int64
	Span    int
}

var (
	orgRefPattern     = regexp.MustCompile(`^org:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	versionPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	effectNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	nodePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:#-]{0,199}$`)
	unitPattern       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	systemPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)

	stages  = []string{"draft", "approval-required", "constrained-live", "certified-live"}
	kinds   = []string{"human", "agent", "service"}
	risks   = []string{"low", "medium", "high", "irreversible"}
	measure = []string{"sum", "count", "distinct"}
	windows = []string{"none", "hour", "day", "month"}
)

// maxSafeInteger is 2^53-1: the plan digest is a JCS digest, and JCS numbers
// are exact only up to it.
const maxSafeInteger = 9007199254740991

// Bounds of one plan, as its schema states them.
const (
	maxPlanEffectTypes = 64
	maxPlanPrincipals  = 2048
	maxPlanMandates    = 4096
	maxPlanLimits      = 8192
	maxPlanTargets     = 256
)

// ParsePlan parses raw as the arguments of effectType, one of the two plan
// effects: the closed schema, then the rules the schema cannot state. The
// bytes are at most MaxPlanBytes, UTF-8, with no duplicate key (checked by the
// caller's Validate, which runs this).
func ParsePlan(effectType string, raw []byte) (*Plan, error) {
	if !IsAuthorityPlan(effectType) {
		return nil, invalid("%s is not an authority plan effect", effectType)
	}
	if len(raw) > MaxPlanBytes {
		return nil, invalid("the plan is %d bytes, more than %d", len(raw), MaxPlanBytes)
	}
	if !utf8.Valid(raw) {
		return nil, invalid("the plan is not UTF-8")
	}
	if err := checkNoDuplicateKeys(raw); err != nil {
		return nil, err
	}
	top, err := asObject(raw, "the plan")
	if err != nil {
		return nil, err
	}
	if err := top.only("schema", "org_ref", "version_ref", "stage", "base_plan_digest", "valid_from", "valid_until",
		"effect_types", "principals", "disable_principals", "mandates", "limits"); err != nil {
		return nil, err
	}
	for _, key := range []string{"schema", "org_ref", "version_ref", "stage", "base_plan_digest", "valid_from", "valid_until",
		"effect_types", "principals", "mandates"} {
		if _, ok := top.fields[key]; !ok {
			return nil, invalid("%s is required", key)
		}
	}
	p := &Plan{}
	if p.Schema, err = top.text("schema"); err != nil {
		return nil, err
	}
	if p.Schema != effectType {
		return nil, invalid("schema must be %q", effectType)
	}
	if p.OrgRef, err = top.match("org_ref", orgRefPattern); err != nil {
		return nil, err
	}
	if p.VersionRef, err = top.match("version_ref", versionPattern); err != nil {
		return nil, err
	}
	if p.Stage, err = top.oneOf("stage", stages); err != nil {
		return nil, err
	}
	if p.BaseDigest, err = top.text("base_plan_digest"); err != nil {
		return nil, err
	}
	if p.BaseDigest != "" && !digestPattern.MatchString(p.BaseDigest) {
		return nil, invalid("base_plan_digest is empty or 64 lower-case hexadecimal characters")
	}
	if p.ValidFrom, err = top.timestamp("valid_from"); err != nil {
		return nil, err
	}
	if p.ValidUntil, err = top.timestamp("valid_until"); err != nil {
		return nil, err
	}
	if !p.ValidUntil.After(p.ValidFrom) {
		return nil, invalid("valid_until must be after valid_from")
	}
	if err := p.parseEffectTypes(top); err != nil {
		return nil, err
	}
	if err := p.parsePrincipals(top); err != nil {
		return nil, err
	}
	if err := p.parseMandates(top); err != nil {
		return nil, err
	}
	if err := p.parseLimits(top); err != nil {
		return nil, err
	}
	if err := p.checkTree(); err != nil {
		return nil, err
	}
	digest, err := planDigest(raw)
	if err != nil {
		return nil, err
	}
	p.Digest = digest
	return p, nil
}

// planDigest is the plan digest: SHA-256 of the RFC 8785 form of the plan
// without base_plan_digest. The numbers of a plan are integers of at most
// 2^53-1, which the interoperable JCS accepts and prints as they are written.
func planDigest(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return "", invalid("the plan is not one JSON object")
	}
	delete(doc, "base_plan_digest")
	canonical, err := canonicalize.InteroperableJCS(doc)
	if err != nil {
		return "", invalid("the plan has no canonical form: %v", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (p *Plan) parseEffectTypes(top object) error {
	items, err := top.array("effect_types", maxPlanEffectTypes)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, item := range items {
		path := fmt.Sprintf("effect_types[%d]", i)
		o, err := asObject(item, path)
		if err != nil {
			return err
		}
		if err := o.only("effect_type", "risk_class"); err != nil {
			return err
		}
		var e PlanEffectType
		if e.EffectType, err = o.matchAt(path, "effect_type", effectNamePattern); err != nil {
			return err
		}
		if strings.HasPrefix(e.EffectType, "helm.authority.") {
			return invalid("%s: %q is the gateway's own effect, which no tenant registers", path, e.EffectType)
		}
		if e.RiskClass, err = o.oneOfAt(path, "risk_class", risks); err != nil {
			return err
		}
		if seen[e.EffectType] {
			return invalid("%s: effect type %q is listed twice", path, e.EffectType)
		}
		seen[e.EffectType] = true
		p.EffectTypes = append(p.EffectTypes, e)
	}
	return nil
}

func (p *Plan) parsePrincipals(top object) error {
	items, err := top.array("principals", maxPlanPrincipals)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, item := range items {
		path := fmt.Sprintf("principals[%d]", i)
		o, err := asObject(item, path)
		if err != nil {
			return err
		}
		if err := o.only("id", "kind", "ensure_only", "external_subject"); err != nil {
			return err
		}
		var pr PlanPrincipal
		if pr.ID, err = o.principalID(path, "id"); err != nil {
			return err
		}
		if pr.Kind, err = o.oneOfAt(path, "kind", kinds); err != nil {
			return err
		}
		if raw, ok := o.fields["ensure_only"]; ok {
			if pr.EnsureOnly, err = boolean(raw, path+".ensure_only"); err != nil {
				return err
			}
		}
		if raw, ok := o.fields["external_subject"]; ok {
			ext, err := asObject(raw, path+".external_subject")
			if err != nil {
				return err
			}
			if err := ext.only("system", "id"); err != nil {
				return err
			}
			pe := &PlanExternal{}
			if pe.System, err = ext.matchAt(path+".external_subject", "system", systemPattern); err != nil {
				return err
			}
			if pe.ID, err = ext.text("id"); err != nil {
				return err
			}
			if pe.ID == "" || len(pe.ID) > 255 || strings.IndexFunc(pe.ID, unicode.IsControl) >= 0 {
				return invalid("%s.external_subject.id is 1 to 255 bytes without control characters", path)
			}
			pr.External = pe
		}
		if pr.Kind == "human" && pr.External == nil && !pr.EnsureOnly {
			return invalid("%s: a human the plan may create carries an external_subject; one that must already be registered is ensure_only", path)
		}
		if seen[pr.ID] {
			return invalid("%s: principal %q is listed twice", path, pr.ID)
		}
		seen[pr.ID] = true
		p.Principals = append(p.Principals, pr)
	}
	if raw, ok := top.fields["disable_principals"]; ok {
		list, err := arrayOf(raw, "disable_principals", maxPlanPrincipals)
		if err != nil {
			return err
		}
		disabled := map[string]bool{}
		for i, item := range list {
			id, err := principalIDOf(item, fmt.Sprintf("disable_principals[%d]", i))
			if err != nil {
				return err
			}
			if disabled[id] {
				return invalid("disable_principals lists %q twice", id)
			}
			if seen[id] {
				return invalid("principal %q is both listed and disabled", id)
			}
			disabled[id] = true
			p.Disable = append(p.Disable, id)
		}
	}
	return nil
}

func (p *Plan) parseMandates(top object) error {
	items, err := top.array("mandates", maxPlanMandates)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return invalid("mandates must list at least the root mandate")
	}
	seen := map[string]bool{}
	for i, item := range items {
		path := fmt.Sprintf("mandates[%d]", i)
		o, err := asObject(item, path)
		if err != nil {
			return err
		}
		if err := o.only("node", "holder", "parent", "terms"); err != nil {
			return err
		}
		for _, key := range []string{"node", "holder", "parent", "terms"} {
			if _, ok := o.fields[key]; !ok {
				return invalid("%s.%s is required", path, key)
			}
		}
		var m PlanMandate
		if m.Node, err = o.matchAt(path, "node", nodePattern); err != nil {
			return err
		}
		if m.Holder, err = o.principalID(path, "holder"); err != nil {
			return err
		}
		if bytes.Equal(bytes.TrimSpace(o.fields["parent"]), []byte("null")) {
			m.Parent = ""
		} else if m.Parent, err = o.matchAt(path, "parent", nodePattern); err != nil {
			return err
		}
		if m.Terms, err = parseTerms(o.fields["terms"], path+".terms"); err != nil {
			return err
		}
		if seen[m.Node] {
			return invalid("%s: node %q is listed twice", path, m.Node)
		}
		seen[m.Node] = true
		p.Mandates = append(p.Mandates, m)
	}
	return nil
}

func parseTerms(raw json.RawMessage, path string) (PlanTerms, error) {
	var t PlanTerms
	o, err := asObject(raw, path)
	if err != nil {
		return t, err
	}
	if err := o.only("effect_types", "targets", "approval_required", "approval_threshold", "per_call_limit", "condition", "risk_classes"); err != nil {
		return t, err
	}
	for _, key := range []string{"effect_types", "targets"} {
		if _, ok := o.fields[key]; !ok {
			return t, invalid("%s.%s is required", path, key)
		}
	}
	if t.EffectTypes, err = nameSet(o.fields["effect_types"], path+".effect_types", 1, maxPlanEffectTypes); err != nil {
		return t, err
	}
	for _, name := range t.EffectTypes {
		if strings.HasPrefix(name, "helm.authority.") {
			return t, invalid("%s.effect_types: %q is the gateway's own effect; no mandate grants it", path, name)
		}
	}
	if !bytes.Equal(bytes.TrimSpace(o.fields["targets"]), []byte("null")) {
		list, err := arrayOf(o.fields["targets"], path+".targets", maxPlanTargets)
		if err != nil {
			return t, err
		}
		if len(list) == 0 {
			return t, invalid("%s.targets is null (any target) or lists at least one", path)
		}
		seen := map[string]bool{}
		for i, item := range list {
			s, err := stringOf(item, fmt.Sprintf("%s.targets[%d]", path, i))
			if err != nil {
				return t, err
			}
			if s == "" || len(s) > 512 || strings.IndexFunc(s, unicode.IsControl) >= 0 {
				return t, invalid("%s.targets[%d] is 1 to 512 bytes without control characters", path, i)
			}
			if seen[s] {
				return t, invalid("%s.targets lists %q twice", path, s)
			}
			seen[s] = true
			t.Targets = append(t.Targets, s)
		}
	}
	if raw, ok := o.fields["approval_required"]; ok {
		if t.ApprovalRequired, err = nameSet(raw, path+".approval_required", 1, maxPlanEffectTypes); err != nil {
			return t, err
		}
		for _, name := range t.ApprovalRequired {
			if !slices.Contains(t.EffectTypes, name) {
				return t, invalid("%s.approval_required: %q is not in the mandate's effect types", path, name)
			}
		}
	}
	if raw, ok := o.fields["approval_threshold"]; ok {
		v, err := integer(raw, path+".approval_threshold", 0, maxSafeInteger)
		if err != nil {
			return t, err
		}
		t.ApprovalThreshold = &v
	}
	if raw, ok := o.fields["per_call_limit"]; ok {
		v, err := integer(raw, path+".per_call_limit", 0, maxSafeInteger)
		if err != nil {
			return t, err
		}
		t.PerCallLimit = &v
	}
	if raw, ok := o.fields["condition"]; ok {
		if t.Condition, err = stringOf(raw, path+".condition"); err != nil {
			return t, err
		}
		if t.Condition == "" || len(t.Condition) > 4096 {
			return t, invalid("%s.condition is 1 to 4096 bytes", path)
		}
	}
	if raw, ok := o.fields["risk_classes"]; ok {
		classes, err := asObject(raw, path+".risk_classes")
		if err != nil {
			return t, err
		}
		if len(classes.fields) > maxPlanEffectTypes {
			return t, invalid("%s.risk_classes has more than %d entries", path, maxPlanEffectTypes)
		}
		t.RiskClasses = map[string]string{}
		for name, rawClass := range classes.fields {
			if !effectNamePattern.MatchString(name) || !slices.Contains(t.EffectTypes, name) {
				return t, invalid("%s.risk_classes: %q is not one of the mandate's effect types", path, name)
			}
			class, err := stringOf(rawClass, path+".risk_classes."+name)
			if err != nil {
				return t, err
			}
			if !slices.Contains(risks, class) {
				return t, invalid("%s.risk_classes.%s is not a risk class", path, name)
			}
			t.RiskClasses[name] = class
		}
	}
	return t, nil
}

func (p *Plan) parseLimits(top object) error {
	raw, ok := top.fields["limits"]
	if !ok {
		return nil
	}
	items, err := arrayOf(raw, "limits", maxPlanLimits)
	if err != nil {
		return err
	}
	nodes := map[string]bool{}
	for _, m := range p.Mandates {
		nodes[m.Node] = true
	}
	shapes := map[[5]string]bool{}
	for i, item := range items {
		path := fmt.Sprintf("limits[%d]", i)
		o, err := asObject(item, path)
		if err != nil {
			return err
		}
		if err := o.only("node", "unit", "measure", "window", "value", "span"); err != nil {
			return err
		}
		for _, key := range []string{"node", "unit", "measure", "window", "value"} {
			if _, ok := o.fields[key]; !ok {
				return invalid("%s.%s is required", path, key)
			}
		}
		l := PlanLimit{Span: 1}
		if l.Node, err = o.matchAt(path, "node", nodePattern); err != nil {
			return err
		}
		if !nodes[l.Node] {
			return invalid("%s: node %q is not a mandate of the plan", path, l.Node)
		}
		if l.Unit, err = o.matchAt(path, "unit", unitPattern); err != nil {
			return err
		}
		if l.Measure, err = o.oneOfAt(path, "measure", measure); err != nil {
			return err
		}
		if l.Window, err = o.oneOfAt(path, "window", windows); err != nil {
			return err
		}
		if l.Value, err = integer(o.fields["value"], path+".value", 0, maxSafeInteger); err != nil {
			return err
		}
		if raw, ok := o.fields["span"]; ok {
			span, err := integer(raw, path+".span", 1, 744)
			if err != nil {
				return err
			}
			l.Span = int(span)
		}
		if l.Span != 1 && (l.Window == "none" || l.Measure == "distinct") {
			return invalid("%s: a %s %s limit has one bucket", path, l.Window, l.Measure)
		}
		shape := [5]string{l.Node, l.Unit, l.Measure, l.Window, strconv.Itoa(l.Span)}
		if shapes[shape] {
			return invalid("%s: node %q has two limits of the same unit, measure, window and span", path, l.Node)
		}
		shapes[shape] = true
		p.Limits = append(p.Limits, l)
	}
	return nil
}

// checkTree requires one root, whose node is the org_ref, every other parent to
// be a node of the plan, and the parents to form a tree that reaches the root.
func (p *Plan) checkTree() error {
	parent := map[string]string{}
	root := ""
	for _, m := range p.Mandates {
		parent[m.Node] = m.Parent
		if m.Parent == "" {
			if root != "" {
				return invalid("mandates %q and %q both have no parent; the plan has one root", root, m.Node)
			}
			root = m.Node
		}
	}
	if root == "" {
		return invalid("no mandate is the root: one has a null parent")
	}
	if root != p.OrgRef {
		return invalid("the root mandate's node is %q, want the org_ref %q", root, p.OrgRef)
	}
	for _, m := range p.Mandates {
		if m.Parent == m.Node {
			return invalid("mandate %q is its own parent", m.Node)
		}
		if _, ok := parent[m.Parent]; m.Parent != "" && !ok {
			return invalid("mandate %q has parent %q, which is not a node of the plan", m.Node, m.Parent)
		}
		steps := 0
		for at := m.Node; parent[at] != ""; at = parent[at] {
			if steps++; steps > len(p.Mandates) {
				return invalid("mandate %q is in a cycle", m.Node)
			}
		}
	}
	registered := map[string]bool{}
	for _, e := range p.EffectTypes {
		registered[e.EffectType] = true
	}
	for _, m := range p.Mandates {
		for _, name := range m.Terms.EffectTypes {
			if !registered[name] {
				return invalid("mandate %q names effect type %q, which effect_types does not list", m.Node, name)
			}
		}
		if slices.Contains(p.Disable, m.Holder) {
			return invalid("mandate %q is held by %q, which the plan disables", m.Node, m.Holder)
		}
	}
	return nil
}

// Holders returns the holders of the plan's mandates, each once.
func (p *Plan) Holders() []string {
	var out []string
	for _, m := range p.Mandates {
		if !slices.Contains(out, m.Holder) {
			out = append(out, m.Holder)
		}
	}
	return out
}

// object is a JSON object read by exact key: encoding/json would fold case
// ("Head", "HEAD" and "ſchema" match "head" and "schema"), so a plan is read
// through its raw members and never through struct tags.
type object struct {
	fields map[string]json.RawMessage
	path   string
}

func asObject(raw json.RawMessage, path string) (object, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return object{}, invalid("%s is not a JSON object", path)
	}
	return object{fields: fields, path: path}, nil
}

// only refuses any key that is not, byte for byte, one of allowed.
func (o object) only(allowed ...string) error {
	for key := range o.fields {
		if !slices.Contains(allowed, key) {
			return invalid("unknown field %q in %s (field names are exact and case-sensitive)", key, o.path)
		}
	}
	return nil
}

func (o object) text(key string) (string, error) {
	return stringOf(o.fields[key], o.path+"."+key)
}

func (o object) match(key string, pattern *regexp.Regexp) (string, error) {
	return o.matchAt(o.path, key, pattern)
}

func (o object) matchAt(path, key string, pattern *regexp.Regexp) (string, error) {
	s, err := stringOf(o.fields[key], path+"."+key)
	if err != nil {
		return "", err
	}
	if !pattern.MatchString(s) {
		return "", invalid("%s.%s %q does not match %s", path, key, s, pattern)
	}
	return s, nil
}

func (o object) oneOf(key string, allowed []string) (string, error) {
	return o.oneOfAt(o.path, key, allowed)
}

func (o object) oneOfAt(path, key string, allowed []string) (string, error) {
	s, err := stringOf(o.fields[key], path+"."+key)
	if err != nil {
		return "", err
	}
	if !slices.Contains(allowed, s) {
		return "", invalid("%s.%s %q is not one of %v", path, key, s, allowed)
	}
	return s, nil
}

func (o object) principalID(path, key string) (string, error) {
	return principalIDOf(o.fields[key], path+"."+key)
}

func (o object) timestamp(key string) (time.Time, error) {
	s, err := o.text(key)
	if err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, invalid("%s is not an RFC 3339 date-time", key)
	}
	// The store keeps microseconds; the plan means the instant the store keeps.
	return t.UTC().Truncate(time.Microsecond), nil
}

func (o object) array(key string, max int) ([]json.RawMessage, error) {
	return arrayOf(o.fields[key], o.path+"."+key, max)
}

func stringOf(raw json.RawMessage, path string) (string, error) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", invalid("%s is not a string", path)
	}
	return s, nil
}

func principalIDOf(raw json.RawMessage, path string) (string, error) {
	s, err := stringOf(raw, path)
	if err != nil {
		return "", err
	}
	if s == "" || len(s) > 255 || !utf8.ValidString(s) || strings.TrimSpace(s) != s || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return "", invalid("%s is 1 to 255 bytes without control characters or edge whitespace", path)
	}
	return s, nil
}

func boolean(raw json.RawMessage, path string) (bool, error) {
	switch string(bytes.TrimSpace(raw)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, invalid("%s is not a boolean", path)
}

// integer reads a JSON integer literal in [lo, hi]. A literal with a fraction
// or an exponent is refused, even where its value is whole: the plan digest
// prints numbers as they are written.
func integer(raw json.RawMessage, path string, lo, hi int64) (int64, error) {
	text := string(bytes.TrimSpace(raw))
	v, err := strconv.ParseInt(text, 10, 64)
	if err != nil || strings.HasPrefix(text, "-") || strings.HasPrefix(text, "+") || v < lo || v > hi {
		return 0, invalid("%s is an integer from %d to %d", path, lo, hi)
	}
	return v, nil
}

func arrayOf(raw json.RawMessage, path string, max int) ([]json.RawMessage, error) {
	var items []json.RawMessage
	if len(raw) == 0 || bytes.TrimSpace(raw)[0] != '[' || json.Unmarshal(raw, &items) != nil {
		return nil, invalid("%s is not an array", path)
	}
	if len(items) > max {
		return nil, invalid("%s has %d entries, more than %d", path, len(items), max)
	}
	return items, nil
}

// nameSet reads an array of distinct effect type names.
func nameSet(raw json.RawMessage, path string, lo, hi int) ([]string, error) {
	items, err := arrayOf(raw, path, hi)
	if err != nil {
		return nil, err
	}
	if len(items) < lo {
		return nil, invalid("%s lists at least %d", path, lo)
	}
	var out []string
	for i, item := range items {
		s, err := stringOf(item, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return nil, err
		}
		if !effectNamePattern.MatchString(s) {
			return nil, invalid("%s[%d] %q is not an effect type", path, i, s)
		}
		if slices.Contains(out, s) {
			return nil, invalid("%s lists %q twice", path, s)
		}
		out = append(out, s)
	}
	return out, nil
}
