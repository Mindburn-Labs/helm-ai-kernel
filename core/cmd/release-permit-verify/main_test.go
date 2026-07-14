package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/releasepermit"
)

func TestDecodeStrictReviewAcceptsExactShape(t *testing.T) {
	var review releasepermit.Review
	if _, err := decodeStrictFile(writeJSONFixture(t, validReviewJSON()), &review); err != nil {
		t.Fatalf("decodeStrictFile() error = %v", err)
	}
	if review.Findings == nil {
		t.Fatal("Findings = nil, want explicit empty array")
	}
}

func TestDecodeStrictReviewRejectsAmbiguousShapes(t *testing.T) {
	valid := validReviewJSON()
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "duplicate key",
			content: strings.Replace(valid, `"verdict":"ALLOW"`, `"verdict":"ALLOW","verdict":"DENY"`, 1),
			want:    `duplicate JSON key "verdict"`,
		},
		{
			name:    "case folded key",
			content: strings.Replace(valid, `"verdict":"ALLOW"`, `"Verdict":"ALLOW"`, 1),
			want:    "keys invalid",
		},
		{
			name:    "null findings",
			content: strings.Replace(valid, `"findings":[]`, `"findings":null`, 1),
			want:    "findings must be an explicit array",
		},
		{
			name:    "missing findings",
			content: strings.Replace(valid, `,"findings":[]`, "", 1),
			want:    "missing=findings",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var review releasepermit.Review
			_, err := decodeStrictFile(writeJSONFixture(t, test.content), &review)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decodeStrictFile() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func writeJSONFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func validReviewJSON() string {
	return `{"schema":"mindburn.release-review/v1","repository":"Mindburn-Labs/example","pull_request":42,"base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","workflow_sha":"3333333333333333333333333333333333333333","run_id":101,"run_attempt":1,"context_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","reviewer":{"provider":"anthropic","model":"claude-fable-5"},"verdict":"ALLOW","response_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","findings":[]}`
}
