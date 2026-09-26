package effectargs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const target = "github.com/Mindburn-Labs/example"

// ValidBranch and ValidDraft are known-good argument documents.
const (
	validBranch = `{"schema":"helm.github.branch.create_from_changes.v1","base":"main",` +
		`"base_sha":"0123456789abcdef0123456789abcdef01234567","head":"helm/skeleton","message":"Add skeleton",` +
		`"files":[{"path":"docs/skeleton.md","mode":"100644","content_utf8":"# Skeleton\n"}]}`
	validDraft = `{"schema":"helm.github.pull_request.create_draft.v1",` +
		`"branch_attempt_id":"0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d","base":"main","head":"helm/skeleton",` +
		`"head_sha":"89abcdef0123456789abcdef0123456789abcdef","title":"Skeleton","body":""}`
)

func TestValidateAcceptsTheSkeletonArguments(t *testing.T) {
	for effectType, raw := range map[string]string{GitHubBranchCreateFromChanges: validBranch, GitHubPullRequestCreateDraft: validDraft} {
		args, err := Validate(effectType, target, []byte(raw))
		if err != nil {
			t.Fatalf("%s: %v", effectType, err)
		}
		if args["head"] != "helm/skeleton" {
			t.Fatalf("%s: parsed arguments = %v", effectType, args)
		}
	}
	for _, raw := range []string{`{"schema":"helm.github.repository.get.v1"}`, `{"schema":"helm.github.repository.get.v1","branch":"helm/skeleton"}`} {
		if _, err := Validate(GitHubRepositoryGet, target, []byte(raw)); err != nil {
			t.Fatalf("repository.get %s: %v", raw, err)
		}
	}
	// An effect type without a closed schema still needs one JSON object.
	if _, err := Validate("ops.note", "anything", []byte(`{"text":"hi"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRefusesMalformedArguments(t *testing.T) {
	replace := func(doc, old, new string) string {
		if !strings.Contains(doc, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(doc, old, new, 1)
	}
	for _, test := range []struct {
		name, effectType, target, raw string
	}{
		{"not an object", "ops.note", "x", `["a"]`},
		{"not JSON", "ops.note", "x", `{"a":`},
		{"trailing data", "ops.note", "x", `{"a":1} {"b":2}`},
		{"duplicate key", "ops.note", "x", `{"a":1,"a":2}`},
		{"nested duplicate key", GitHubBranchCreateFromChanges, target, replace(validBranch, `"mode":"100644"`, `"mode":"100644","mode":"100755"`)},
		{"not UTF-8", "ops.note", "x", "{\"a\":\"\xff\"}"},
		{"oversize", "ops.note", "x", `{"a":"` + strings.Repeat("x", MaxBytes) + `"}`},
		{"unknown field", GitHubBranchCreateFromChanges, target, replace(validBranch, `"base":"main"`, `"base":"main","force":true`)},
		{"repository in the arguments", GitHubPullRequestCreateDraft, target, replace(validDraft, `"base":"main"`, `"base":"main","repo":"other"`)},
		{"missing field", GitHubPullRequestCreateDraft, target, replace(validDraft, `"branch_attempt_id":"0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d",`, ``)},
		{"wrong schema", GitHubBranchCreateFromChanges, target, replace(validBranch, `create_from_changes.v1"`, `create_from_changes.v2"`)},
		{"short base_sha", GitHubBranchCreateFromChanges, target, replace(validBranch, `"base_sha":"0123456789abcdef0123456789abcdef01234567"`, `"base_sha":"0123"`)},
		{"uppercase head_sha", GitHubPullRequestCreateDraft, target, replace(validDraft, `89abcdef0123456789abcdef0123456789abcdef`, `89ABCDEF0123456789ABCDEF0123456789ABCDEF`)},
		{"head is a ref", GitHubBranchCreateFromChanges, target, replace(validBranch, `"head":"helm/skeleton"`, `"head":"refs/heads/helm/x"`)},
		{"head with ..", GitHubBranchCreateFromChanges, target, replace(validBranch, `"head":"helm/skeleton"`, `"head":"helm/../main"`)},
		{"head component starting with a dot", GitHubBranchCreateFromChanges, target, replace(validBranch, `"head":"helm/skeleton"`, `"head":"helm/.hidden"`)},
		{"no files", GitHubBranchCreateFromChanges, target, replace(validBranch, `[{"path":"docs/skeleton.md","mode":"100644","content_utf8":"# Skeleton\n"}]`, `[]`)},
		{"symlink mode", GitHubBranchCreateFromChanges, target, replace(validBranch, `"mode":"100644"`, `"mode":"120000"`)},
		{"traversal path", GitHubBranchCreateFromChanges, target, replace(validBranch, `"path":"docs/skeleton.md"`, `"path":"docs/../../etc/passwd"`)},
		{"workflow file", GitHubBranchCreateFromChanges, target, replace(validBranch, `"path":"docs/skeleton.md"`, `"path":".github/workflows/x.yml"`)},
		{"inside .git", GitHubBranchCreateFromChanges, target, replace(validBranch, `"path":"docs/skeleton.md"`, `"path":".git/config"`)},
		{"absolute path", GitHubBranchCreateFromChanges, target, replace(validBranch, `"path":"docs/skeleton.md"`, `"path":"/etc/passwd"`)},
		{"path not NFC", GitHubBranchCreateFromChanges, target, replace(validBranch, `"path":"docs/skeleton.md"`, "\"path\":\"docs/café.md\"")},
		{"repeated path", GitHubBranchCreateFromChanges, target, replace(validBranch, `]}`, `,{"path":"docs/skeleton.md","mode":"100644","content_utf8":"x"}]}`)},
		{"empty title", GitHubPullRequestCreateDraft, target, replace(validDraft, `"title":"Skeleton"`, `"title":""`)},
		{"target with a path", GitHubBranchCreateFromChanges, target + "/pull/1", validBranch},
		{"target on another host", GitHubBranchCreateFromChanges, "gitlab.com/o/r", validBranch},
		{"repository.get with a ref", GitHubRepositoryGet, target, `{"schema":"helm.github.repository.get.v1","branch":"refs/heads/main"}`},
		{"repository.get with a repo field", GitHubRepositoryGet, target, `{"schema":"helm.github.repository.get.v1","repo":"other"}`},
		{"repository.get without its schema", GitHubRepositoryGet, target, `{"branch":"main"}`},
		{"repository.get over 4 KiB", GitHubRepositoryGet, target, `{"schema":"helm.github.repository.get.v1","branch":"` + strings.Repeat("a", 4100) + `"}`},
	} {
		if _, err := Validate(test.effectType, test.target, []byte(test.raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", test.name, err)
		}
	}
}

// The HELM-753 fixtures (protocols/json-schemas/effects/github/examples),
// when they are in the tree: every valid fixture passes and every invalid
// one is refused, so this validator and the JSON Schemas agree.
func TestValidateAgreesWithTheSchemaFixtures(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "protocols", "json-schemas", "effects", "github", "examples")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("the HELM-753 GitHub effect fixtures are not in this tree yet (PR #1054)")
	}
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		var effectType string
		switch {
		case strings.HasPrefix(name, "branch_create_from_changes.v1."):
			effectType = GitHubBranchCreateFromChanges
		case strings.HasPrefix(name, "pull_request_create_draft.v1."):
			effectType = GitHubPullRequestCreateDraft
		case strings.HasPrefix(name, "repository_get.v1."):
			effectType = GitHubRepositoryGet
		default:
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		_, err = Validate(effectType, target, raw)
		valid := strings.Contains(name, ".valid.")
		if valid && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if !valid && err == nil {
			t.Errorf("%s: accepted an invalid fixture", name)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("found the fixture directory but no GitHub effect fixture in it")
	}
}

// M1: encoding/json folds field names (with Unicode folding), so a document
// could say one thing to the condition's map and another to the typed struct.
// Every key must be an exact field name.
func TestValidateRefusesKeysThatOnlyFoldToAFieldName(t *testing.T) {
	cases := map[string]struct{ effectType, raw string }{
		"branch Head":          {GitHubBranchCreateFromChanges, strings.Replace(validBranch, `"head":"helm/skeleton"`, `"head":"helm/skeleton","Head":"release"`, 1)},
		"branch HEAD":          {GitHubBranchCreateFromChanges, strings.Replace(validBranch, `"head":"helm/skeleton"`, `"HEAD":"helm/skeleton"`, 1)},
		"branch long-s schema": {GitHubBranchCreateFromChanges, strings.Replace(validBranch, `"schema":`, "\"\u017fchema\":", 1)},
		"branch file Path":     {GitHubBranchCreateFromChanges, strings.Replace(validBranch, `"path":"docs/skeleton.md"`, `"Path":"docs/skeleton.md"`, 1)},
		"draft Head":           {GitHubPullRequestCreateDraft, strings.Replace(validDraft, `"head":"helm/skeleton"`, `"head":"helm/skeleton","Head":"release"`, 1)},
		"draft HEAD":           {GitHubPullRequestCreateDraft, strings.Replace(validDraft, `"head":"helm/skeleton"`, `"HEAD":"helm/skeleton"`, 1)},
		"draft long-s schema":  {GitHubPullRequestCreateDraft, strings.Replace(validDraft, `"schema":`, "\"\u017fchema\":", 1)},
		"read Branch":          {GitHubRepositoryGet, `{"schema":"helm.github.repository.get.v1","Branch":"main"}`},
		"read BRANCH":          {GitHubRepositoryGet, `{"schema":"helm.github.repository.get.v1","branch":"helm/x","BRANCH":"main"}`},
		"read long-s schema":   {GitHubRepositoryGet, "{\"\u017fchema\":\"helm.github.repository.get.v1\"}"},
	}
	for name, c := range cases {
		if _, err := Validate(c.effectType, target, []byte(c.raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	// Known good: the exact names still pass.
	if _, err := Validate(GitHubBranchCreateFromChanges, target, []byte(validBranch)); err != nil {
		t.Fatal(err)
	}
}
