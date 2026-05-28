// Package redact provides zero-leak redaction for sensitive values in structured
// payloads and log lines. It strips API keys, raw file paths, and environment
// variables whose names signal secrets. All patterns are deterministic; short
// strings that happen to look like prefixes are intentionally kept to avoid
// false positives.
package redact

import (
	"fmt"
	"regexp"
	"strings"
)

const placeholder = "[REDACTED]"

// Minimum lengths to prevent false positives on short strings.
const (
	minAPIKeyLen  = 8
	minFilePathLen = 6
)

// apiKeyPatterns matches values that look like API keys / cloud credentials.
// Each pattern requires a minimum prefix + body length to avoid tripping on
// innocent short strings like "skeleton" matching "sk-".
var apiKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bsk-[A-Za-z0-9_-]{4,}\b`),
	regexp.MustCompile(`(?i)\bkey-[A-Za-z0-9_-]{4,}\b`),
	regexp.MustCompile(`\bAKIA[A-Z0-9]{12,}\b`),
}

// filePathPatterns matches raw filesystem paths that leak host info.
var filePathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`/Users/[^\s"',}\]]+`),
	regexp.MustCompile(`/home/[^\s"',}\]]+`),
	regexp.MustCompile(`(?i)C:\\\\[^\s"',}\]]+`),
	regexp.MustCompile(`(?i)C:\\[^\s"',}\]]+`),
}

// secretEnvSuffixes are substrings in env-var names that signal the value
// should never leave the boundary.
var secretEnvSuffixes = []string{"SECRET", "KEY", "TOKEN", "PASSWORD"}

// isSecretEnvName returns true if the key name signals a secret.
func isSecretEnvName(key string) bool {
	upper := strings.ToUpper(key)
	for _, suffix := range secretEnvSuffixes {
		if strings.Contains(upper, suffix) {
			return true
		}
	}
	return false
}

// Redact recursively strips sensitive values from a map.
// It returns a deep copy; the original is never mutated.
func Redact(payload map[string]interface{}) map[string]interface{} {
	if payload == nil {
		return nil
	}
	out := make(map[string]interface{}, len(payload))
	for k, v := range payload {
		out[k] = redactValue(k, v)
	}
	return out
}

func redactValue(key string, v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		if isSecretEnvName(key) {
			return placeholder
		}
		return RedactString(val)
	case map[string]interface{}:
		return Redact(val)
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, elem := range val {
			result[i] = redactValue("", elem)
		}
		return result
	case fmt.Stringer:
		if isSecretEnvName(key) {
			return placeholder
		}
		return RedactString(val.String())
	default:
		return v
	}
}

// RedactString scrubs sensitive patterns from a single string.
func RedactString(s string) string {
	if len(s) < minFilePathLen {
		return s
	}
	for _, re := range apiKeyPatterns {
		s = re.ReplaceAllString(s, placeholder)
	}
	for _, re := range filePathPatterns {
		s = re.ReplaceAllString(s, placeholder)
	}
	return s
}
