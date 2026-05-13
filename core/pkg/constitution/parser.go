package constitution

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// Parser reads agent constitutions from JSON or text format.
type Parser struct{}

// NewParser creates a new constitution parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseJSON parses a constitution from JSON bytes.
//
// It validates required fields (ConstitutionID, AgentID, at least one principle),
// checks for duplicate principle priorities, and computes the content hash via JCS.
func (p *Parser) ParseJSON(data []byte) (*Constitution, error) {
	var c Constitution
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("constitution: invalid JSON: %w", err)
	}

	if c.ConstitutionID == "" {
		return nil, fmt.Errorf("constitution: missing constitution_id")
	}
	if c.AgentID == "" {
		return nil, fmt.Errorf("constitution: missing agent_id")
	}
	if len(c.Principles) == 0 {
		return nil, fmt.Errorf("constitution: at least one principle is required")
	}

	// Validate principles.
	priorities := make(map[int]string, len(c.Principles))
	for i, pr := range c.Principles {
		if pr.ID == "" {
			return nil, fmt.Errorf("constitution: principle[%d] missing id", i)
		}
		if pr.Name == "" {
			return nil, fmt.Errorf("constitution: principle[%d] missing name", i)
		}
		if pr.Priority < 1 {
			return nil, fmt.Errorf("constitution: principle[%d] priority must be >= 1", i)
		}
		if prev, ok := priorities[pr.Priority]; ok {
			return nil, fmt.Errorf("constitution: duplicate priority %d between principles %q and %q", pr.Priority, prev, pr.ID)
		}
		priorities[pr.Priority] = pr.ID
	}

	// Compute content hash via JCS canonicalization.
	// Hash is computed over principles only (the semantic content),
	// not over metadata like CreatedAt or ContentHash itself.
	hashInput := struct {
		ConstitutionID string      `json:"constitution_id"`
		AgentID        string      `json:"agent_id"`
		Version        string      `json:"version"`
		Principles     []Principle `json:"principles"`
	}{
		ConstitutionID: c.ConstitutionID,
		AgentID:        c.AgentID,
		Version:        c.Version,
		Principles:     c.Principles,
	}

	hash, err := canonicalize.CanonicalHash(hashInput)
	if err != nil {
		return nil, fmt.Errorf("constitution: failed to compute content hash: %w", err)
	}
	c.ContentHash = hash

	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}

	return &c, nil
}

// ParsePrinciples extracts principles from a simple numbered text format.
//
// Each line should be a principle in the form "1. Be helpful and honest".
// Categories are auto-assigned based on keyword matching against the text.
// A unique Constitution is generated with a random ID.
func (p *Parser) ParsePrinciples(agentID string, text string) (*Constitution, error) {
	if agentID == "" {
		return nil, fmt.Errorf("constitution: agent_id is required")
	}

	lines := strings.Split(strings.TrimSpace(text), "\n")
	var principles []Principle

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse numbered format: "1. ..." or "2. ..."
		priority, desc, ok := parseNumberedLine(line)
		if !ok {
			continue
		}

		id := fmt.Sprintf("p-%d", priority)
		category := inferCategory(desc)

		principles = append(principles, Principle{
			ID:          id,
			Name:        truncateName(desc, 64),
			Description: desc,
			Priority:    priority,
			Category:    category,
		})
	}

	if len(principles) == 0 {
		return nil, fmt.Errorf("constitution: no valid principles found in text")
	}

	constitutionID, err := randomID("const")
	if err != nil {
		return nil, fmt.Errorf("constitution: failed to generate ID: %w", err)
	}

	c := &Constitution{
		ConstitutionID: constitutionID,
		AgentID:        agentID,
		Version:        "1.0.0",
		Principles:     principles,
		CreatedAt:      time.Now().UTC(),
	}

	// Compute content hash.
	hashInput := struct {
		ConstitutionID string      `json:"constitution_id"`
		AgentID        string      `json:"agent_id"`
		Version        string      `json:"version"`
		Principles     []Principle `json:"principles"`
	}{
		ConstitutionID: c.ConstitutionID,
		AgentID:        c.AgentID,
		Version:        c.Version,
		Principles:     c.Principles,
	}

	hash, err := canonicalize.CanonicalHash(hashInput)
	if err != nil {
		return nil, fmt.Errorf("constitution: failed to compute content hash: %w", err)
	}
	c.ContentHash = hash

	return c, nil
}

// parseNumberedLine extracts priority and text from "N. description" format.
func parseNumberedLine(line string) (int, string, bool) {
	// Find first digit sequence followed by ". "
	var numStr string
	for _, r := range line {
		if unicode.IsDigit(r) {
			numStr += string(r)
		} else {
			break
		}
	}
	if numStr == "" {
		return 0, "", false
	}

	rest := strings.TrimPrefix(line, numStr)
	if !strings.HasPrefix(rest, ".") {
		return 0, "", false
	}
	rest = strings.TrimPrefix(rest, ".")
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return 0, "", false
	}

	var priority int
	for _, r := range numStr {
		priority = priority*10 + int(r-'0')
	}

	return priority, rest, true
}

// categoryEntry pairs a category name with its detection keywords.
// Order matters: more specific categories are checked first so that
// "Protect user privacy" matches privacy, not safety's "protect".
type categoryEntry struct {
	name     string
	keywords []string
}

// categoryOrder defines a deterministic, specificity-ordered list of
// categories and their detection keywords.
var categoryOrder = []categoryEntry{
	{"privacy", []string{"privacy", "private", "personal data", "confidential", "pii", "gdpr"}},
	{"fairness", []string{"fair", "bias", "discriminat", "equit", "equal", "inclusive"}},
	{"honesty", []string{"honest", "truthful", "accurate", "transparent", "deceiv", "mislead", "factual"}},
	{"helpfulness", []string{"helpful", "assist", "useful", "support", "serve", "enable"}},
	{"safety", []string{"safe", "harm", "danger", "risk", "protect", "secure", "security"}},
}

// inferCategory guesses a principle category from keywords in its description.
// Categories are checked in specificity order (most specific first) to avoid
// ambiguity when a description contains keywords from multiple categories.
func inferCategory(desc string) string {
	lower := strings.ToLower(desc)

	for _, entry := range categoryOrder {
		for _, kw := range entry.keywords {
			if strings.Contains(lower, kw) {
				return entry.name
			}
		}
	}

	return "safety" // default to safety (fail-closed)
}

// truncateName truncates a string to maxLen, appending "..." if truncated.
func truncateName(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// randomID generates a prefixed random identifier.
func randomID(prefix string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b)), nil
}
