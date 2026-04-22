// Package provenance implements provenance-tagged context building for
// indirect prompt injection defense. Every context segment carries source
// type, trust level, and transform chain for instruction firewall enforcement.
package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/governance"
)

// Version is the current schema version.
const Version = "1.0.0"

// SourceType classifies the origin of content.
type SourceType string

const (
	SourceSystem      SourceType = "system"
	SourceUser        SourceType = "user"
	SourceToolOutput  SourceType = "tool_output"
	SourceWeb         SourceType = "web"
	SourceFile        SourceType = "file"
	SourceDatabase    SourceType = "database"
	SourceModelOutput SourceType = "model_output"
)

// TrustLevel classifies trust for instruction firewall.
type TrustLevel string

const (
	TrustLevelTrusted     TrustLevel = "trusted"
	TrustLevelSemiTrusted TrustLevel = "semi_trusted"
	TrustLevelUntrusted   TrustLevel = "untrusted"
	TrustLevelAdversarial TrustLevel = "adversarial"
)

// TransformType defines safety transforms.
type TransformType string

const (
	TransformNone      TransformType = "none"
	TransformSpotlight TransformType = "spotlight"
	TransformQuote     TransformType = "quote"
	TransformEscape    TransformType = "escape"
	TransformRedact    TransformType = "redact"
	TransformTokenize  TransformType = "tokenize"
	TransformFilter    TransformType = "filter"
)

// Envelope is a provenance-tagged context container.
type Envelope struct {
	EnvelopeID         string               `json:"envelope_id"`
	Version            string               `json:"version"`
	CreatedAt          time.Time            `json:"created_at"`
	Segments           []*Segment           `json:"segments"`
	FirewallPolicyID   string               `json:"firewall_policy_id,omitempty"`
	DataClassification governance.DataClass `json:"data_classification,omitempty"`
	TransformChain     []Transform          `json:"transform_chain,omitempty"`
	ContentHash        string               `json:"content_hash,omitempty"`
}

// Segment is a single provenance-tagged content segment.
type Segment struct {
	SegmentID           string               `json:"segment_id"`
	SourceType          SourceType           `json:"source_type"`
	TrustLevel          TrustLevel           `json:"trust_level"`
	Content             string               `json:"content"`
	Metadata            SegmentMetadata      `json:"metadata,omitempty"`
	TransformApplied    TransformType        `json:"transform_applied"`
	InjectionIndicators []InjectionIndicator `json:"injection_indicators,omitempty"`
}

// SegmentMetadata contains source information.
type SegmentMetadata struct {
	SourceURI string    `json:"source_uri,omitempty"`
	ToolID    string    `json:"tool_id,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
	UserID    string    `json:"user_id,omitempty"`
}

// Transform represents an applied safety transform.
type Transform struct {
	TransformType  TransformType `json:"transform_type"`
	AppliedAt      time.Time     `json:"applied_at"`
	TargetSegments []string      `json:"target_segments,omitempty"`
	Signature      string        `json:"signature,omitempty"`
}

// InjectionIndicator represents a detected injection pattern.
type InjectionIndicator struct {
	PatternID  string  `json:"pattern_id"`
	Confidence float64 `json:"confidence"`
	Position   int     `json:"position"`
}

// FirewallRule defines an instruction firewall rule.
type FirewallRule struct {
	RuleID     string        `json:"rule_id"`
	Name       string        `json:"name"`
	Priority   int           `json:"priority"`
	SourceType SourceType    `json:"source_type,omitempty"`
	TrustLevel TrustLevel    `json:"trust_level,omitempty"`
	Action     string        `json:"action"` // allow, transform, block
	Transform  TransformType `json:"transform,omitempty"`
	Patterns   []string      `json:"patterns,omitempty"`
}

// FirewallPolicy defines a set of instruction firewall rules.
type FirewallPolicy struct {
	PolicyID      string         `json:"policy_id"`
	Name          string         `json:"name"`
	Rules         []FirewallRule `json:"rules"`
	DefaultAction string         `json:"default_action"`
}

// NewBuilder creates a new provenance envelope builder.
func NewBuilder() *Builder {
	return &Builder{
		envelope: &Envelope{
			EnvelopeID: "env-" + strings.ReplaceAll(uuid.New().String(), "-", ""),
			Version:    Version,
			CreatedAt:  time.Now().UTC(),
			Segments:   make([]*Segment, 0),
		},
		patterns:   make(map[string]*regexp.Regexp),
		classifier: governance.NewClassifier(),
	}
}

// Builder constructs provenance envelopes.
type Builder struct {
	mu         sync.Mutex
	envelope   *Envelope
	policy     *FirewallPolicy
	patterns   map[string]*regexp.Regexp
	classifier *governance.Classifier
}

// SetFirewallPolicy sets the firewall policy for the builder.
func (b *Builder) SetFirewallPolicy(policy *FirewallPolicy) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.policy = policy
	b.envelope.FirewallPolicyID = policy.PolicyID
}

// AddSegment adds a content segment with provenance metadata.
func (b *Builder) AddSegment(sourceType SourceType, trustLevel TrustLevel, content string, metadata SegmentMetadata) *Segment {
	b.mu.Lock()
	defer b.mu.Unlock()

	segment := &Segment{
		SegmentID:        "seg-" + uuid.New().String()[:8],
		SourceType:       sourceType,
		TrustLevel:       trustLevel,
		Content:          content,
		Metadata:         metadata,
		TransformApplied: TransformNone,
	}

	// Detect injection indicators
	segment.InjectionIndicators = b.detectInjection(content)

	// Update Data Classification (Max of existing vs new)
	// We cheat a bit and just re-classify based on everything so far, or just this segment?
	// Real implementation should be: logic to escalate classification if confidential data found.
	class := b.classifier.Classify(content)
	if isHigherSensitivity(class, b.envelope.DataClassification) {
		b.envelope.DataClassification = class
	}

	// Apply firewall rules
	if b.policy != nil {
		segment = b.applyFirewall(segment)
	}

	b.envelope.Segments = append(b.envelope.Segments, segment)
	return segment
}

func isHigherSensitivity(newClass, oldClass governance.DataClass) bool {
	rank := map[governance.DataClass]int{
		governance.DataClassPublic:       0,
		governance.DataClassInternal:     1,
		governance.DataClassConfidential: 2,
		governance.DataClassRestricted:   3,
	}
	// Default empty oldClass to Public (0) if not set, but DataClass zero value is "" which isn't in map.
	// Let's assume empty "" is 0.
	return rank[newClass] > rank[oldClass]
}

// AddSystemPrompt adds a trusted system prompt.
func (b *Builder) AddSystemPrompt(content string) *Segment {
	return b.AddSegment(SourceSystem, TrustLevelTrusted, content, SegmentMetadata{})
}

// AddUserInput adds user-provided content (semi-trusted).
func (b *Builder) AddUserInput(content string, userID string) *Segment {
	return b.AddSegment(SourceUser, TrustLevelSemiTrusted, content, SegmentMetadata{
		UserID:    userID,
		Timestamp: time.Now().UTC(),
	})
}

// AddToolOutput adds tool output (untrusted by default).
func (b *Builder) AddToolOutput(content string, toolID string) *Segment {
	return b.AddSegment(SourceToolOutput, TrustLevelUntrusted, content, SegmentMetadata{
		ToolID:    toolID,
		Timestamp: time.Now().UTC(),
	})
}

// AddWebContent adds web-sourced content (untrusted).
func (b *Builder) AddWebContent(content string, sourceURI string) *Segment {
	return b.AddSegment(SourceWeb, TrustLevelUntrusted, content, SegmentMetadata{
		SourceURI: sourceURI,
		Timestamp: time.Now().UTC(),
	})
}

// Build finalizes the envelope and computes content hash.
func (b *Builder) Build() *Envelope {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Compute content hash
	var contentBuilder strings.Builder
	for _, seg := range b.envelope.Segments {
		contentBuilder.WriteString(seg.Content)
	}
	hash := sha256.Sum256([]byte(contentBuilder.String()))
	b.envelope.ContentHash = hex.EncodeToString(hash[:])

	return b.envelope
}

// RenderForModel renders the envelope as a string for model input.
func (b *Builder) RenderForModel() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	var result strings.Builder
	for _, seg := range b.envelope.Segments {
		result.WriteString(seg.Content)
		result.WriteString("\n")
	}
	return result.String()
}

// detectInjection detects potential prompt injection patterns.
func (b *Builder) detectInjection(content string) []InjectionIndicator {
	var indicators []InjectionIndicator
	lowerContent := strings.ToLower(content)

	// Common injection patterns with confidence scores
	patterns := map[string]float64{
		"ignore.*previous.*instructions?": 0.9,
		"disregard.*above":                0.8,
		"forget.*everything":              0.8,
		"you are now":                     0.7,
		"new instructions?:":              0.7,
		"system prompt:":                  0.9,
		"===.*end.*===":                   0.8,
		"\\[\\[.*\\]\\]":                  0.5,
		"<system>":                        0.9,
		"</system>":                       0.9,
		"actual task:":                    0.7,
		"override:":                       0.6,
	}

	for pattern, confidence := range patterns {
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			continue
		}
		matches := re.FindAllStringIndex(lowerContent, -1)
		for _, match := range matches {
			indicators = append(indicators, InjectionIndicator{
				PatternID:  pattern,
				Confidence: confidence,
				Position:   match[0],
			})
		}
	}

	return indicators
}

// applyFirewall applies firewall rules to a segment.
func (b *Builder) applyFirewall(seg *Segment) *Segment {
	if b.policy == nil {
		return seg
	}

	for _, rule := range b.policy.Rules {
		if !b.ruleMatches(rule, seg) {
			continue
		}

		switch rule.Action {
		case "block":
			seg.Content = "[BLOCKED BY FIREWALL]"
			seg.TransformApplied = TransformFilter
		case "transform":
			seg = b.applyTransform(seg, rule.Transform)
		}

		// Record transform
		b.envelope.TransformChain = append(b.envelope.TransformChain, Transform{
			TransformType:  seg.TransformApplied,
			AppliedAt:      time.Now().UTC(),
			TargetSegments: []string{seg.SegmentID},
		})

		break // First matching rule wins
	}

	return seg
}

// ruleMatches checks if a rule applies to a segment.
func (b *Builder) ruleMatches(rule FirewallRule, seg *Segment) bool {
	if rule.SourceType != "" && rule.SourceType != seg.SourceType {
		return false
	}
	if rule.TrustLevel != "" && rule.TrustLevel != seg.TrustLevel {
		return false
	}
	return true
}

// applyTransform applies a safety transform to content.
func (b *Builder) applyTransform(seg *Segment, transform TransformType) *Segment {
	switch transform {
	case TransformSpotlight:
		// Wrap untrusted content in clear delimiters
		seg.Content = fmt.Sprintf("\n---BEGIN EXTERNAL DATA---\n%s\n---END EXTERNAL DATA---\n", seg.Content)
	case TransformQuote:
		// Quote each line
		lines := strings.Split(seg.Content, "\n")
		for i, line := range lines {
			lines[i] = "> " + line
		}
		seg.Content = strings.Join(lines, "\n")
	case TransformEscape:
		// Escape special characters
		seg.Content = strings.ReplaceAll(seg.Content, "<", "&lt;")
		seg.Content = strings.ReplaceAll(seg.Content, ">", "&gt;")
	}
	seg.TransformApplied = transform
	return seg
}

// ToJSON serializes the envelope to JSON.
func (e *Envelope) ToJSON() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}

// HasInjectionIndicators returns true if any segment has injection indicators.
func (e *Envelope) HasInjectionIndicators() bool {
	for _, seg := range e.Segments {
		if len(seg.InjectionIndicators) > 0 {
			return true
		}
	}
	return false
}

// MaxInjectionConfidence returns the highest injection confidence score.
func (e *Envelope) MaxInjectionConfidence() float64 {
	maxConf := 0.0
	for _, seg := range e.Segments {
		for _, ind := range seg.InjectionIndicators {
			if ind.Confidence > maxConf {
				maxConf = ind.Confidence
			}
		}
	}
	return maxConf
}
