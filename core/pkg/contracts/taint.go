package contracts

import "strings"

const (
	TaintPII        = "pii"
	TaintCredential = "credential"
	TaintSecret     = "secret"
	TaintToolOutput = "tool_output"
	TaintUserInput  = "user_input"
	TaintExternal   = "external"
)

// NormalizeTaintLabels returns stable, lowercase, deduplicated taint labels.
func NormalizeTaintLabels(labels []string) []string {
	if len(labels) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(labels))
	out := make([]string, 0, len(labels))
	for _, label := range labels {
		label = strings.ToLower(strings.TrimSpace(label))
		if label == "" {
			continue
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		out = append(out, label)
	}
	return out
}

func TaintContains(labels []string, label string) bool {
	label = strings.ToLower(strings.TrimSpace(label))
	for _, candidate := range labels {
		if candidate == label {
			return true
		}
	}
	return false
}

func TaintContainsAny(labels []string, candidates ...string) bool {
	for _, candidate := range candidates {
		if TaintContains(labels, candidate) {
			return true
		}
	}
	return false
}

// TaintLabelsFromContext reads taint labels from common context keys.
func TaintLabelsFromContext(ctx map[string]interface{}) []string {
	if ctx == nil {
		return nil
	}
	for _, key := range []string{"taint", "taint_labels"} {
		if labels := labelsFromAny(ctx[key]); len(labels) > 0 {
			return NormalizeTaintLabels(labels)
		}
	}
	return nil
}

func labelsFromAny(value any) []string {
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		return strings.FieldsFunc(v, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
		})
	case []string:
		return v
	case []any:
		labels := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				labels = append(labels, s)
			}
		}
		return labels
	default:
		return nil
	}
}
