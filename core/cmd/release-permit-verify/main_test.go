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

func TestDecodeStrictContextRequiresExactAuthorityShape(t *testing.T) {
	valid := validContextJSON()
	for _, test := range []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "valid",
			content: valid,
		},
		{
			name:    "authority extra key",
			content: strings.Replace(valid, `"generation":2`, `"generation":2,"approval":true`, 1),
			want:    "authority keys invalid",
		},
		{
			name:    "parent extra key",
			content: strings.Replace(valid, `"generation":1,"workflow_sha"`, `"generation":1,"approval":true,"workflow_sha"`, 1),
			want:    "authority.parent keys invalid",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var context releasepermit.Context
			_, err := decodeStrictFile(writeJSONFixture(t, test.content), &context)
			if test.want == "" && err != nil {
				t.Fatalf("decodeStrictFile() error = %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("decodeStrictFile() error = %v, want substring %q", err, test.want)
			}
		})
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
	return `{"schema":"mindburn.release-review/v1","repository":"Mindburn-Labs/example","pull_request":42,"base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","merge_sha":"4444444444444444444444444444444444444444","merge_tree_sha":"5555555555555555555555555555555555555555","workflow_sha":"3333333333333333333333333333333333333333","run_id":101,"run_attempt":1,"context_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","reviewer":{"provider":"anthropic","model":"claude-fable-5"},"verdict":"ALLOW","response_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","findings":[]}`
}

func validContextJSON() string {
	return `{"schema":"mindburn.release-permit-context/v2","repository":"Mindburn-Labs/example","event":"pull_request","pull_request":42,"base_ref":"refs/heads/main","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","merge_sha":"4444444444444444444444444444444444444444","merge_tree_sha":"5555555555555555555555555555555555555555","workflow_repository":"Mindburn-Labs/.github","workflow_path":".github/workflows/ci.yml","workflow_ref":"refs/heads/main","workflow_sha":"3333333333333333333333333333333333333333","run_id":101,"run_attempt":1,"issued_at":"2026-07-14T10:00:00Z","authority":{"schema":"mindburn.release-authority/v1","generation":2,"kernel_sha":"6666666666666666666666666666666666666666","gate_profiles_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","adversarial_corpus_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","parent":{"generation":1,"workflow_sha":"7777777777777777777777777777777777777777"}},"required_reviewers":[{"provider":"anthropic","model":"claude-fable-5"},{"provider":"openai","model":"gpt-5.6-sol"}]}`
}
