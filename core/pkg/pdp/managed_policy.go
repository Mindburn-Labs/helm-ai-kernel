package pdp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	ManagedPolicyArtifactKind = "helm-policy-bundle-json"
	ManagedPolicySchemaV1     = "helm.kernel.managed-policy.v1"
	MaxManagedPolicyBytes     = 1 << 20
	maxManagedPolicyRules     = 512

	ManagedPolicyLayerP0 = "P0"
	ManagedPolicyLayerP1 = "P1"
	ManagedPolicyLayerP2 = "P2"
)

// ManagedPolicyBundle is the Control Plane publication consumed by Kernel.
// KernelRuntime is the only executable section; the other layers remain
// source-owned evidence and are hash-bound into the installed snapshot.
type ManagedPolicyBundle struct {
	P0Ceilings           json.RawMessage      `json:"p0_ceilings"`
	P1Bundle             json.RawMessage      `json:"p1_bundle"`
	P2Overlay            json.RawMessage      `json:"p2_overlay"`
	ApprovalRoutes       json.RawMessage      `json:"approval_routes"`
	Department           string               `json:"department,omitempty"`
	PolicyPackID         string               `json:"policy_pack_id,omitempty"`
	ApprovalProfile      string               `json:"approval_profile,omitempty"`
	SourceLanguage       string               `json:"source_language"`
	SourceHash           string               `json:"source_hash"`
	ReadableSummary      string               `json:"readable_summary,omitempty"`
	CompiledArtifactKind string               `json:"compiled_artifact_kind"`
	KernelRuntime        ManagedPolicyRuntime `json:"kernel_runtime"`
}

type ManagedPolicyRuntime struct {
	SchemaVersion  string              `json:"schema_version"`
	DefaultVerdict contracts.Verdict   `json:"default_verdict"`
	Rules          []ManagedPolicyRule `json:"rules"`
}

// ManagedPolicyRule uses AND semantics across its non-empty selectors.
type ManagedPolicyRule struct {
	ID          string            `json:"id"`
	Layer       string            `json:"layer"`
	EffectClass string            `json:"effect_class,omitempty"`
	Action      string            `json:"action,omitempty"`
	Resource    string            `json:"resource,omitempty"`
	Pattern     string            `json:"pattern,omitempty"`
	Verdict     contracts.Verdict `json:"verdict"`
	Reason      string            `json:"reason"`
}

type compiledManagedPolicyRule struct {
	ManagedPolicyRule
	pattern *regexp.Regexp
}

// ManagedPolicyPDP evaluates the normalized, signed Control Plane policy.
type ManagedPolicyPDP struct {
	rules          []compiledManagedPolicyRule
	policyHash     string
	p0CeilingsHash string
	p1BundleHash   string
	p2OverlayHash  string
}

func NewManagedPolicyPDP(data []byte, sourceRefs []string) (*ManagedPolicyPDP, error) {
	if len(data) == 0 || len(data) > MaxManagedPolicyBytes {
		return nil, fmt.Errorf("pdp/managed: bundle size must be between 1 and %d bytes", MaxManagedPolicyBytes)
	}
	var bundle ManagedPolicyBundle
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return nil, fmt.Errorf("pdp/managed: decode bundle: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("pdp/managed: bundle must contain exactly one JSON value")
	}
	if bundle.CompiledArtifactKind != ManagedPolicyArtifactKind {
		return nil, fmt.Errorf("pdp/managed: compiled_artifact_kind must be %q", ManagedPolicyArtifactKind)
	}
	if !validSHA256Ref(bundle.SourceHash) || !containsExact(sourceRefs, bundle.SourceHash) {
		return nil, fmt.Errorf("pdp/managed: source_hash must be canonical and present in signed source_refs")
	}
	if strings.TrimSpace(bundle.SourceLanguage) == "" {
		return nil, fmt.Errorf("pdp/managed: source_language is required")
	}
	for name, raw := range map[string]json.RawMessage{
		"p0_ceilings":     bundle.P0Ceilings,
		"p1_bundle":       bundle.P1Bundle,
		"p2_overlay":      bundle.P2Overlay,
		"approval_routes": bundle.ApprovalRoutes,
	} {
		if err := requireJSONObject(name, raw); err != nil {
			return nil, err
		}
	}
	if bundle.KernelRuntime.SchemaVersion != ManagedPolicySchemaV1 {
		return nil, fmt.Errorf("pdp/managed: kernel_runtime.schema_version must be %q", ManagedPolicySchemaV1)
	}
	if bundle.KernelRuntime.DefaultVerdict != contracts.VerdictDeny {
		return nil, fmt.Errorf("pdp/managed: kernel_runtime.default_verdict must be DENY")
	}
	rules, err := compileManagedPolicyRules(bundle.KernelRuntime.Rules)
	if err != nil {
		return nil, err
	}
	p0Hash, err := canonicalJSONHash(bundle.P0Ceilings)
	if err != nil {
		return nil, fmt.Errorf("pdp/managed: hash p0_ceilings: %w", err)
	}
	p1Hash, err := canonicalJSONHash(bundle.P1Bundle)
	if err != nil {
		return nil, fmt.Errorf("pdp/managed: hash p1_bundle: %w", err)
	}
	p2Hash, err := canonicalJSONHash(bundle.P2Overlay)
	if err != nil {
		return nil, fmt.Errorf("pdp/managed: hash p2_overlay: %w", err)
	}
	return &ManagedPolicyPDP{
		rules:          rules,
		policyHash:     canonicalize.ComputeArtifactHash(data),
		p0CeilingsHash: p0Hash,
		p1BundleHash:   p1Hash,
		p2OverlayHash:  p2Hash,
	}, nil
}

func compileManagedPolicyRules(input []ManagedPolicyRule) ([]compiledManagedPolicyRule, error) {
	if len(input) == 0 || len(input) > maxManagedPolicyRules {
		return nil, fmt.Errorf("pdp/managed: kernel_runtime.rules must contain 1..%d rules", maxManagedPolicyRules)
	}
	seen := make(map[string]struct{}, len(input))
	rules := make([]compiledManagedPolicyRule, 0, len(input))
	hasP0E4Deny := false
	hasP1E3Escalate := false
	for i, rule := range input {
		if !validManagedToken(rule.ID, 128) {
			return nil, fmt.Errorf("pdp/managed: rule %d has invalid id", i)
		}
		if _, ok := seen[rule.ID]; ok {
			return nil, fmt.Errorf("pdp/managed: duplicate rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		switch rule.Layer {
		case ManagedPolicyLayerP0:
			if rule.Verdict != contracts.VerdictDeny {
				return nil, fmt.Errorf("pdp/managed: P0 rule %q must DENY", rule.ID)
			}
		case ManagedPolicyLayerP1:
		case ManagedPolicyLayerP2:
			if rule.Verdict == contracts.VerdictAllow {
				return nil, fmt.Errorf("pdp/managed: P2 rule %q cannot widen policy with ALLOW", rule.ID)
			}
		default:
			return nil, fmt.Errorf("pdp/managed: rule %q has invalid layer %q", rule.ID, rule.Layer)
		}
		switch rule.Verdict {
		case contracts.VerdictAllow, contracts.VerdictDeny, contracts.VerdictEscalate:
		default:
			return nil, fmt.Errorf("pdp/managed: rule %q has invalid verdict %q", rule.ID, rule.Verdict)
		}
		if rule.Reason == "" || rule.Reason != strings.TrimSpace(rule.Reason) || len(rule.Reason) > 1024 || strings.ContainsAny(rule.Reason, "\x00\r\n") {
			return nil, fmt.Errorf("pdp/managed: rule %q has invalid reason", rule.ID)
		}
		selectors := 0
		if rule.EffectClass != "" {
			selectors++
			if !contracts.ValidEffectClass(rule.EffectClass) {
				return nil, fmt.Errorf("pdp/managed: rule %q has invalid effect_class %q", rule.ID, rule.EffectClass)
			}
		}
		for name, value := range map[string]string{"action": rule.Action, "resource": rule.Resource} {
			if value != "" {
				selectors++
				if !validManagedSelector(value) {
					return nil, fmt.Errorf("pdp/managed: rule %q has invalid %s", rule.ID, name)
				}
			}
		}
		compiled := compiledManagedPolicyRule{ManagedPolicyRule: rule}
		if rule.Pattern != "" {
			selectors++
			if rule.Pattern != strings.TrimSpace(rule.Pattern) || len(rule.Pattern) > 256 {
				return nil, fmt.Errorf("pdp/managed: rule %q has invalid pattern", rule.ID)
			}
			pattern, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return nil, fmt.Errorf("pdp/managed: rule %q pattern: %w", rule.ID, err)
			}
			compiled.pattern = pattern
		}
		if selectors == 0 {
			return nil, fmt.Errorf("pdp/managed: rule %q requires at least one selector", rule.ID)
		}
		if rule.Layer == ManagedPolicyLayerP0 && rule.EffectClass == "E4" && rule.Action == "" && rule.Resource == "" && rule.Pattern == "" && rule.Verdict == contracts.VerdictDeny {
			hasP0E4Deny = true
		}
		if rule.Layer == ManagedPolicyLayerP1 && rule.EffectClass == "E3" && rule.Action == "" && rule.Resource == "" && rule.Pattern == "" && rule.Verdict == contracts.VerdictEscalate {
			hasP1E3Escalate = true
		}
		rules = append(rules, compiled)
	}
	if !hasP0E4Deny {
		return nil, fmt.Errorf("pdp/managed: P0 must deny E4")
	}
	if !hasP1E3Escalate {
		return nil, fmt.Errorf("pdp/managed: P1 must escalate E3")
	}
	return rules, nil
}

func (p *ManagedPolicyPDP) Evaluate(ctx context.Context, req *DecisionRequest) (*DecisionResponse, error) {
	if req == nil {
		return p.denyResponse(string(contracts.ReasonSchemaViolation))
	}
	if err := ctx.Err(); err != nil {
		return p.denyResponse(string(contracts.ReasonPDPError))
	}
	var readings managedPolicyReadings
	if err := readings.bind(req); err != nil {
		return p.denyResponse(string(contracts.ReasonPDPError))
	}
	matchedAllow := false
	matchedEscalate := false
	for _, rule := range p.rules {
		matched, err := readings.matches(rule)
		if err != nil {
			return p.denyResponse(string(contracts.ReasonPDPError))
		}
		if !matched {
			continue
		}
		switch rule.Verdict {
		case contracts.VerdictDeny:
			return p.denyResponse(string(contracts.ReasonPDPDeny))
		case contracts.VerdictEscalate:
			matchedEscalate = true
		case contracts.VerdictAllow:
			matchedAllow = true
		}
	}
	if matchedEscalate {
		return p.denyResponse(string(contracts.ReasonApprovalRequired))
	}
	if !matchedAllow {
		return p.denyResponse(string(contracts.ReasonPDPDeny))
	}
	resp := &DecisionResponse{Allow: true, PolicyRef: p.policyRef()}
	if err := attachDecisionHash(resp); err != nil {
		return denyForHashFailure(p.policyRef(), err)
	}
	return resp, nil
}

// managedPolicyCandidate is the canonical text of a request. Pattern rules
// match it without the provenance members (managedPolicyReadings).
func managedPolicyCandidate(req *DecisionRequest) ([]byte, error) {
	return canonicalize.JCS(struct {
		Action   string         `json:"action"`
		Resource string         `json:"resource"`
		Context  map[string]any `json:"context,omitempty"`
	}{Action: req.Action, Resource: req.Resource, Context: req.Context})
}

// managedPolicyReadings are the readings of one request that a rule is
// matched against. A rule matches the request when it matches one of them.
//
// Without the provenance members: the request as the transport bound it,
// without effect_class_source and effect_class_declared. This is the text a
// pattern written before those members existed was written for. They sort
// right after effect_class in the canonical text (only a member whose name
// begins with effect_class can come between), so in the text as bound a
// pattern written when effect_class was followed by the next context member
// would stop matching: a restriction would lapse and an allow would turn into
// a denial. No pattern is matched against the text as bound, so none reads
// either member at the top level: an allow pattern cannot match the
// declaration the caller chose or the source the kernel bound, and a pattern
// that names one matches only a member of that name the caller nested.
// effect_class is the bound class in this reading.
//
// As declared: when the transport kept the caller's own value under
// effect_class_declared because it bound a different class, the reading
// without the provenance members with effect_class holding that value, so a
// rule that restricts on what the caller declared still applies. Allow rules
// are never matched against it.
//
// Selectors read effect_class, the action and the resource as values, so only
// a pattern needs a reading's text. Where a transport bound a provenance
// member, the text is built when the first pattern needs it, cut from the
// canonical text of the request as bound.
type managedPolicyReadings struct {
	req           *DecisionRequest
	candidate     []byte
	boundClass    string
	hasBoundClass bool
	// provenance: a transport bound effect_class_source or
	// effect_class_declared, so the reading without them is not the text as
	// bound.
	provenance bool
	// declaredClass is the caller's own value the transport kept; the reading
	// as declared exists only when it is set.
	declaredClass string

	withoutProvenance []byte
	asDeclared        []byte
}

// bind sets the readings to those of req.
func (r *managedPolicyReadings) bind(req *DecisionRequest) error {
	candidate, err := managedPolicyCandidate(req)
	if err != nil {
		return err
	}
	*r = managedPolicyReadings{req: req, candidate: candidate}
	r.boundClass, r.hasBoundClass = req.Context["effect_class"].(string)
	_, hasSource := req.Context["effect_class_source"]
	_, hasDeclared := req.Context["effect_class_declared"]
	r.provenance = hasSource || hasDeclared
	if declared, ok := req.Context["effect_class_declared"].(string); ok {
		r.declaredClass = declared
	}
	return nil
}

// matches reports whether rule matches one of the readings of the request.
func (r *managedPolicyReadings) matches(rule compiledManagedPolicyRule) (bool, error) {
	if rule.matchesSelectors(r.req, r.boundClass, r.hasBoundClass) {
		if rule.pattern == nil {
			return true, nil
		}
		text, err := r.withoutProvenanceText()
		if err != nil {
			return false, err
		}
		if rule.pattern.Match(text) {
			return true, nil
		}
	}
	// Allow rules are never matched against the request as declared, so a
	// declared class there can add a restriction and never lift one.
	if rule.Verdict == contracts.VerdictAllow || r.declaredClass == "" {
		return false, nil
	}
	if !rule.matchesSelectors(r.req, r.declaredClass, true) {
		return false, nil
	}
	if rule.pattern == nil {
		return true, nil
	}
	text, err := r.asDeclaredText()
	if err != nil {
		return false, err
	}
	return rule.pattern.Match(text), nil
}

// withoutProvenanceText returns the text of the reading without the
// provenance members, which is the text as bound when a transport bound
// neither.
func (r *managedPolicyReadings) withoutProvenanceText() ([]byte, error) {
	if !r.provenance {
		return r.candidate, nil
	}
	if r.withoutProvenance == nil {
		text, ok := r.cutReading(false)
		if !ok {
			var err error
			if text, err = canonicalManagedPolicyReading(r.req, ""); err != nil {
				return nil, err
			}
		}
		r.withoutProvenance = text
	}
	return r.withoutProvenance, nil
}

func (r *managedPolicyReadings) asDeclaredText() ([]byte, error) {
	if r.asDeclared == nil {
		text, ok := r.cutReading(true)
		if !ok {
			var err error
			if text, err = canonicalManagedPolicyReading(r.req, r.declaredClass); err != nil {
				return nil, err
			}
		}
		r.asDeclared = text
	}
	return r.asDeclared, nil
}

// canonicalManagedPolicyReading canonicalizes the request without the
// provenance members, with effect_class set to effectClass when it is not
// empty. It defines the text of the other readings: cutReading reproduces it
// byte for byte, and it is used where cutReading cannot.
func canonicalManagedPolicyReading(req *DecisionRequest, effectClass string) ([]byte, error) {
	view := *req
	view.Context = make(map[string]any, len(req.Context))
	for key, value := range req.Context {
		view.Context[key] = value
	}
	delete(view.Context, "effect_class_source")
	delete(view.Context, "effect_class_declared")
	if effectClass != "" {
		view.Context["effect_class"] = effectClass
	}
	return managedPolicyCandidate(&view)
}

// cutReading returns the text of the reading without the provenance members,
// or as declared, taken from the canonical text of the request as bound.
// Removing members from a canonical object leaves the canonical object
// without them, because each member is written on its own and in key order;
// and the declared value is already in that text in canonical form, as the
// value of effect_class_declared. ok is false where the cut text would not be
// the canonical one: the reading has no context member left (the canonical
// text then has no context), the request has no effect_class to replace, or
// the text is not of the shape managedPolicyCandidate writes.
func (r *managedPolicyReadings) cutReading(asDeclared bool) ([]byte, bool) {
	text := r.candidate
	var buffer [32]canonicalMember
	members, contextOpen, contextClose, ok := scanCanonicalContext(buffer[:0], text)
	if !ok {
		return nil, false
	}
	var declaredValue []byte
	if asDeclared {
		for _, member := range members {
			if member.hasKey(text, `"effect_class_declared"`) {
				declaredValue = text[member.valueStart:member.end]
			}
		}
		if declaredValue == nil {
			return nil, false
		}
	}
	out := make([]byte, 0, len(text))
	out = append(out, text[:contextOpen+1]...)
	kept, replaced := 0, false
	for _, member := range members {
		if member.hasKey(text, `"effect_class_source"`) || member.hasKey(text, `"effect_class_declared"`) {
			continue
		}
		if kept > 0 {
			out = append(out, ',')
		}
		kept++
		if asDeclared && member.hasKey(text, `"effect_class"`) {
			out = append(out, text[member.start:member.valueStart]...)
			out = append(out, declaredValue...)
			replaced = true
			continue
		}
		out = append(out, text[member.start:member.end]...)
	}
	if kept == 0 || (asDeclared && !replaced) {
		return nil, false
	}
	return append(out, text[contextClose:]...), true
}

// canonicalMember is one member of the context object in a canonical
// candidate: where it starts, where its value starts and where it ends.
type canonicalMember struct {
	start, valueStart, end int
}

// hasKey reports whether the member's key, as written with its quotes, is
// key. A canonical key has exactly one spelling, so it compares as a plain
// string.
func (m canonicalMember) hasKey(text []byte, key string) bool {
	return string(text[m.start:m.valueStart-1]) == key
}

// scanCanonicalContext appends to members the members of the context object
// in text that managedPolicyCandidate wrote,
// {"action":...,"context":{...},"resource":...}, and returns them with the
// offsets of that object's braces. ok is false for text of any other shape.
// Canonical text has no whitespace, so the scan follows strings and nesting
// and nothing else.
func scanCanonicalContext(members []canonicalMember, text []byte) (_ []canonicalMember, open, close int, ok bool) {
	const actionHead, contextHead, resourceHead = `{"action":`, `,"context":{`, `,"resource":`
	if !hasTextAt(text, 0, actionHead) {
		return nil, 0, 0, false
	}
	i, ok := skipCanonicalString(text, len(actionHead))
	if !ok || !hasTextAt(text, i, contextHead) {
		return nil, 0, 0, false
	}
	open = i + len(contextHead) - 1
	i = open + 1
	for {
		start := i
		if i, ok = skipCanonicalString(text, i); !ok || i >= len(text) || text[i] != ':' {
			return nil, 0, 0, false
		}
		valueStart := i + 1
		if i, ok = skipCanonicalValue(text, valueStart); !ok || i >= len(text) {
			return nil, 0, 0, false
		}
		members = append(members, canonicalMember{start: start, valueStart: valueStart, end: i})
		switch text[i] {
		case ',':
			i++
		case '}':
			close = i
			if !hasTextAt(text, close+1, resourceHead) {
				return nil, 0, 0, false
			}
			end, ok := skipCanonicalString(text, close+1+len(resourceHead))
			if !ok || end != len(text)-1 || text[end] != '}' {
				return nil, 0, 0, false
			}
			return members, open, close, true
		default:
			return nil, 0, 0, false
		}
	}
}

func hasTextAt(text []byte, i int, want string) bool {
	return i >= 0 && len(text)-i >= len(want) && string(text[i:i+len(want)]) == want
}

// skipCanonicalString returns the offset after the JSON string at text[i].
func skipCanonicalString(text []byte, i int) (int, bool) {
	if i >= len(text) || text[i] != '"' {
		return i, false
	}
	for i++; i < len(text); i++ {
		switch text[i] {
		case '\\':
			i++
		case '"':
			return i + 1, true
		}
	}
	return i, false
}

// skipCanonicalValue returns the offset after the JSON value at text[i].
func skipCanonicalValue(text []byte, i int) (int, bool) {
	if i >= len(text) {
		return i, false
	}
	switch text[i] {
	case '"':
		return skipCanonicalString(text, i)
	case '{', '[':
		depth := 0
		for i < len(text) {
			switch text[i] {
			case '"':
				var ok bool
				if i, ok = skipCanonicalString(text, i); !ok {
					return i, false
				}
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1, true
				}
			}
			i++
		}
		return i, false
	default:
		start := i
		for i < len(text) && text[i] != ',' && text[i] != '}' && text[i] != ']' {
			i++
		}
		return i, i > start
	}
}

// matchesSelectors reports whether the rule's selectors match the request
// with effectClass as its effect_class.
func (r compiledManagedPolicyRule) matchesSelectors(req *DecisionRequest, effectClass string, hasEffectClass bool) bool {
	if r.EffectClass != "" && (!hasEffectClass || effectClass != r.EffectClass) {
		return false
	}
	if r.Action != "" && req.Action != r.Action {
		return false
	}
	return r.Resource == "" || req.Resource == r.Resource
}

func (p *ManagedPolicyPDP) Backend() Backend   { return BackendHELM }
func (p *ManagedPolicyPDP) PolicyHash() string { return p.policyHash }

// AuthoritativeAllow reports that this strictly validated, source-bound
// managed bundle replaces local PRG evaluation for matching ALLOW decisions.
func (p *ManagedPolicyPDP) AuthoritativeAllow() bool { return true }

func (p *ManagedPolicyPDP) LayerHashes() (string, string, []string) {
	return p.p0CeilingsHash, p.p1BundleHash, []string{p.p2OverlayHash}
}

func (p *ManagedPolicyPDP) denyResponse(reason string) (*DecisionResponse, error) {
	resp := &DecisionResponse{Allow: false, ReasonCode: reason, PolicyRef: p.policyRef()}
	if err := attachDecisionHash(resp); err != nil {
		return denyForHashFailure(p.policyRef(), err)
	}
	return resp, nil
}

func (p *ManagedPolicyPDP) policyRef() string { return "helm-managed:" + p.policyHash }

func requireJSONObject(name string, raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return fmt.Errorf("pdp/managed: %s must be a JSON object", name)
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &value); err != nil || value == nil {
		return fmt.Errorf("pdp/managed: %s must be a JSON object", name)
	}
	return nil
}

func canonicalJSONHash(raw json.RawMessage) (string, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	canonical, err := canonicalize.JCS(value)
	if err != nil {
		return "", err
	}
	return canonicalize.ComputeArtifactHash(canonical), nil
}

func validSHA256Ref(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	raw := strings.TrimPrefix(value, "sha256:")
	decoded, err := hex.DecodeString(raw)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == raw
}

func containsExact(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func validManagedToken(value string, max int) bool {
	if value == "" || len(value) > max || value != strings.TrimSpace(value) {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		return false
	}
	return true
}

func validManagedSelector(value string) bool {
	return value == strings.TrimSpace(value) && len(value) <= 512 && !strings.ContainsAny(value, "\x00\r\n\t")
}
