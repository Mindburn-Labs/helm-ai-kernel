package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func TestDecodeStrictFileRejectsOversizedInputBeforeDecode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.json")
	if err := os.WriteFile(path, make([]byte, maxInputBytes+1), 0o600); err != nil {
		t.Fatalf("write oversized fixture: %v", err)
	}
	var review releasepermit.Review
	if _, err := decodeStrictFile(path, &review); err == nil || !strings.Contains(err.Error(), "input exceeds") {
		t.Fatalf("decodeStrictFile() error = %v, want input size error", err)
	}
}

func TestDecodeStrictFileRejectsSymlinkInput(t *testing.T) {
	target := writeJSONFixture(t, validReviewJSON())
	link := filepath.Join(t.TempDir(), "review.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	var review releasepermit.Review
	if _, err := decodeStrictFile(link, &review); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("decodeStrictFile() error = %v, want regular-file rejection", err)
	}
}

func TestDecodeStrictPermitAcceptsExactShape(t *testing.T) {
	var permit releasepermit.Permit
	if _, err := decodeStrictFile(writeJSONFixture(t, validPermitJSON()), &permit); err != nil {
		t.Fatalf("decodeStrictFile() error = %v", err)
	}
	if permit.Reviews == nil || permit.Reasons == nil {
		t.Fatal("Reviews and Reasons must be explicit arrays")
	}
}

func TestDecodeStrictPermitRejectsNullReviewCounts(t *testing.T) {
	content := strings.Replace(validPermitJSON(), `"blocking_findings":0`, `"blocking_findings":null`, 1)
	var permit releasepermit.Permit
	if _, err := decodeStrictFile(writeJSONFixture(t, content), &permit); err == nil ||
		!strings.Contains(err.Error(), "reviews[0].blocking_findings must not be null") {
		t.Fatalf("decodeStrictFile() error = %v, want null count rejection", err)
	}
}

func TestVerifyPermitFileRejectsTamperedPermit(t *testing.T) {
	path := writeJSONFixture(t, validPermitJSON())
	contextPath := writeJSONFixture(t, validContextJSON())
	if _, err := verifyPermitFile(path, contextPath); err == nil || !strings.Contains(err.Error(), "permit_id") {
		t.Fatalf("verifyPermitFile() error = %v, want permit digest rejection", err)
	}
}

func TestVerifyPermitFileAcceptsReducerPermitAgainstTrustedContext(t *testing.T) {
	contextContent := []byte(validContextJSON())
	var context releasepermit.Context
	if err := json.Unmarshal(contextContent, &context); err != nil {
		t.Fatalf("decode context fixture: %v", err)
	}
	contextDigest := sha256.Sum256(contextContent)
	contextSHA256 := hex.EncodeToString(contextDigest[:])
	reviews := make([]releasepermit.Review, 0, len(context.RequiredReviewers))
	for index, reviewer := range context.RequiredReviewers {
		reviews = append(reviews, releasepermit.Review{
			Schema:         releasepermit.ReviewSchema,
			Repository:     context.Repository,
			PullRequest:    context.PullRequest,
			BaseSHA:        context.BaseSHA,
			HeadSHA:        context.HeadSHA,
			MergeSHA:       context.MergeSHA,
			MergeTreeSHA:   context.MergeTreeSHA,
			WorkflowSHA:    context.WorkflowSHA,
			RunID:          context.RunID,
			RunAttempt:     context.RunAttempt,
			ContextSHA256:  contextSHA256,
			Reviewer:       reviewer,
			Verdict:        releasepermit.DecisionAllow,
			ResponseSHA256: strings.Repeat(string(rune('a'+index)), 64),
			Findings:       []releasepermit.Finding{},
		})
	}
	permit, err := releasepermit.Evaluate(context, contextSHA256, reviews)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	permitContent, err := json.Marshal(permit)
	if err != nil {
		t.Fatalf("encode permit: %v", err)
	}
	permitPath := writeJSONFixture(t, string(permitContent))
	contextPath := writeJSONFixture(t, string(contextContent))
	if _, err := verifyPermitFile(permitPath, contextPath); err != nil {
		t.Fatalf("verifyPermitFile() error = %v", err)
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

func TestDecodeStrictContextAllowsBootstrapNullParent(t *testing.T) {
	content := strings.Replace(validContextJSON(), `"generation":2`, `"generation":1`, 1)
	content = strings.Replace(content, `{"generation":1,"workflow_sha":"7777777777777777777777777777777777777777"}`, `null`, 1)
	var context releasepermit.Context
	if _, err := decodeStrictFile(writeJSONFixture(t, content), &context); err != nil {
		t.Fatalf("decodeStrictFile() error = %v", err)
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
			want:    "findings must not be null",
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

func validPermitJSON() string {
	return `{"schema":"mindburn.release-permit/v2","permit_id":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","decision":"ALLOW","repository":"Mindburn-Labs/example","pull_request":42,"base_ref":"refs/heads/main","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","merge_sha":"4444444444444444444444444444444444444444","merge_tree_sha":"5555555555555555555555555555555555555555","workflow_repository":"Mindburn-Labs/.github","workflow_path":".github/workflows/ci.yml","workflow_ref":"refs/heads/main","workflow_sha":"3333333333333333333333333333333333333333","run_id":101,"run_attempt":1,"issued_at":"2026-07-14T10:00:00Z","authority":{"schema":"mindburn.release-authority/v1","generation":2,"kernel_sha":"6666666666666666666666666666666666666666","gate_profiles_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","adversarial_corpus_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","parent":{"generation":1,"workflow_sha":"7777777777777777777777777777777777777777"}},"context_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","reviews":[{"reviewer":{"provider":"anthropic","model":"claude-fable-5"},"verdict":"ALLOW","response_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","blocking_findings":0,"advisory_findings":0},{"reviewer":{"provider":"openai","model":"gpt-5.6-sol"},"verdict":"ALLOW","response_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","blocking_findings":0,"advisory_findings":0}],"reasons":[]}`
}

func TestWritePermitFileRejectsSymlinkOutput(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "release-permit.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writePermitFile(link, []byte("overwritten")); err == nil {
		t.Fatal("writePermitFile accepted a symlinked output path")
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "{}" {
		t.Fatalf("symlink target was overwritten: %q", content)
	}
}

func TestWritePermitFileCreatesOwnerOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release-permit.json")
	if err := writePermitFile(path, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("permit file mode = %o, want 600", perm)
	}
}
