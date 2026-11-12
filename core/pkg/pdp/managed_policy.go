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
	candidate, err := managedPolicyCandidate(req)
	if err != nil {
		return p.denyResponse(string(contracts.ReasonPDPError))
	}
	// A restricting rule is also matched against the other readings of the
	// request. They can only add a match, so allow rules never see them: a
	// declaration can add a restriction and never lift one.
	restrictingViews, err := managedPolicyRestrictingViews(req)
	if err != nil {
		return p.denyResponse(string(contracts.ReasonPDPError))
	}
	matchedAllow := false
	matchedEscalate := false
	for _, rule := range p.rules {
		matched := rule.matches(req, candidate)
		if !matched && rule.Verdict != contracts.VerdictAllow {
			for _, view := range restrictingViews {
				if rule.matches(view.request, view.candidate) {
					matched = true
					break
				}
			}
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

// managedPolicyCandidate is the canonical text pattern rules match.
func managedPolicyCandidate(req *DecisionRequest) ([]byte, error) {
	return canonicalize.JCS(struct {
		Action   string         `json:"action"`
		Resource string         `json:"resource"`
		Context  map[string]any `json:"context,omitempty"`
	}{Action: req.Action, Resource: req.Resource, Context: req.Context})
}

// managedPolicyView is one reading of a request and the canonical text that
// pattern rules match for it.
type managedPolicyView struct {
	request   *DecisionRequest
	candidate []byte
}

// managedPolicyRestrictingViews returns the readings of a request that deny
// and escalate rules are matched against besides the request as it was bound.
// It returns none when no transport bound where the class came from.
//
// As bound, without effect_class_source and effect_class_declared. Those two
// members sort directly after effect_class in the canonical text, so a pattern
// written when effect_class was followed by the next context member would
// stop matching once a transport binds them, and a restriction would lapse.
//
// As declared, when the transport kept the caller's own value under
// effect_class_declared because it bound a different class: the same reading
// with effect_class holding that value, so a rule that restricts on what the
// caller declared still applies.
func managedPolicyRestrictingViews(req *DecisionRequest) ([]managedPolicyView, error) {
	_, hasSource := req.Context["effect_class_source"]
	_, hasDeclared := req.Context["effect_class_declared"]
	if !hasSource && !hasDeclared {
		return nil, nil
	}
	withoutProvenance := func(effectClass string) (managedPolicyView, error) {
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
		candidate, err := managedPolicyCandidate(&view)
		return managedPolicyView{request: &view, candidate: candidate}, err
	}
	asBound, err := withoutProvenance("")
	if err != nil {
		return nil, err
	}
	views := []managedPolicyView{asBound}
	if declaredClass, ok := req.Context["effect_class_declared"].(string); ok && declaredClass != "" {
		asDeclared, err := withoutProvenance(declaredClass)
		if err != nil {
			return nil, err
		}
		views = append(views, asDeclared)
	}
	return views, nil
}

func (r compiledManagedPolicyRule) matches(req *DecisionRequest, candidate []byte) bool {
	if r.EffectClass != "" {
		effectClass, ok := req.Context["effect_class"].(string)
		if !ok || effectClass != r.EffectClass {
			return false
		}
	}
	if r.Action != "" && req.Action != r.Action {
		return false
	}
	if r.Resource != "" && req.Resource != r.Resource {
		return false
	}
	return r.pattern == nil || r.pattern.Match(candidate)
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
