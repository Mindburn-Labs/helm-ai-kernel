package github

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

func schemasDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "..", "protocols", "json-schemas", "effects", "github")
}

// The contract's known-good and known-bad fixtures: every valid example
// parses and every invalid one is refused.
func TestSchemaExamples(t *testing.T) {
	examples, err := filepath.Glob(filepath.Join(schemasDir(t), "examples", "*.json"))
	if err != nil || len(examples) < 10 {
		t.Fatalf("found %d examples: %v", len(examples), err)
	}
	for _, path := range examples {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(path)
		parse := func() error { _, err := parseBranchArgs(raw); return err }
		switch {
		case strings.HasPrefix(name, "pull_request_create_draft"):
			parse = func() error { _, err := parsePullRequestArgs(raw); return err }
		case strings.HasPrefix(name, "repository_get"):
			parse = func() error { _, err := parseRepositoryArgs(raw); return err }
		}
		err = parse()
		if strings.Contains(name, ".valid.") && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if strings.Contains(name, ".invalid-") && !refusedWith(err, contracts.ReasonSchemaViolation) {
			t.Errorf("%s was accepted (%v)", name, err)
		}
	}
}

const validBranch = `{"schema":"helm.github.branch.create_from_changes.v1","base":"main",` +
	`"base_sha":"0123456789abcdef0123456789abcdef01234567","head":"helm/x","message":"m",` +
	`"files":[{"path":"a.md","mode":"100644","content_utf8":"a"}]}`

const validPullRequest = `{"schema":"helm.github.pull_request.create_draft.v1",` +
	`"branch_attempt_id":"0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d","base":"main","head":"helm/x",` +
	`"head_sha":"0123456789abcdef0123456789abcdef01234567","title":"t","body":""}`

func TestArgumentRulesBeyondTheSchema(t *testing.T) {
	if _, err := parseBranchArgs([]byte(validBranch)); err != nil {
		t.Fatalf("the valid branch: %v", err)
	}
	if _, err := parsePullRequestArgs([]byte(validPullRequest)); err != nil {
		t.Fatalf("the valid pull request: %v", err)
	}
	branch := func(old, new string) string { return strings.Replace(validBranch, old, new, 1) }
	pr := func(old, new string) string { return strings.Replace(validPullRequest, old, new, 1) }
	big := strings.Repeat("x", maxContentBytes)
	for name, raw := range map[string]string{
		"duplicate key":           branch(`"base":"main",`, `"base":"main","base":"dev",`),
		"nested duplicate key":    branch(`"mode":"100644",`, `"mode":"100644","mode":"100755",`),
		"case-folded key":         branch(`"head":`, `"HEAD":`),
		"unknown key":             branch(`"message":"m",`, `"message":"m","repo":"o/r",`),
		"missing key":             branch(`"message":"m",`, ``),
		"null value":              pr(`"body":""`, `"body":null`),
		"number for string":       branch(`"message":"m"`, `"message":1`),
		"trailing content":        validBranch + `{}`,
		"invalid UTF-8":           branch(`"m"`, "\"\xff\""),
		"lone surrogate":          branch(`"m"`, `"\ud800"`),
		"not NFC":                 branch(`"a.md"`, "\"é.md\""),
		"repeated path":           branch(`}]}`, `},{"path":"a.md","mode":"100644","content_utf8":"b"}]}`),
		"workflow file":           branch(`"a.md"`, `".github/workflows/x.yml"`),
		"dot-git":                 branch(`"a.md"`, `".git/config"`),
		"traversal":               branch(`"a.md"`, `"docs/../a.md"`),
		"backslash":               branch(`"a.md"`, `"a\\b.md"`),
		"symlink mode":            branch(`"100644"`, `"120000"`),
		"content over bytes":      branch(`"content_utf8":"a"`, `"content_utf8":"`+strings.Repeat("é", maxContentBytes/2+1)+`"`),
		"content over characters": branch(`"content_utf8":"a"`, `"content_utf8":"`+big+`x"`),
		"head is a ref":           branch(`"helm/x"`, `"refs/heads/x"`),
		"head has ..":             branch(`"helm/x"`, `"helm/../x"`),
		"head ends .lock":         branch(`"helm/x"`, `"helm/x.lock"`),
		"head starts with -":      branch(`"helm/x"`, `"-x"`),
		"head component dot":      branch(`"helm/x"`, `"helm/.x"`),
		"uppercase base_sha":      branch(`0123456789abcdef`, `0123456789ABCDEF`),
		"no files":                branch(`[{"path":"a.md","mode":"100644","content_utf8":"a"}]`, `[]`),
		"files not array":         branch(`[{"path":"a.md","mode":"100644","content_utf8":"a"}]`, `{}`),
		"too large":               branch(`"m"`, `"`+strings.Repeat(" ", maxArgumentBytes)+`"`),
		"body over bytes":         pr(`"body":""`, `"body":"`+strings.Repeat("é", maxBodyBytes/2+1)+`"`),
		"bad attempt id":          pr(`0192f0c4`, `0192F0C4`),
		"wrong schema":            pr(`create_draft.v1`, `create_draft.v2`),
	} {
		var err error
		if strings.Contains(raw, "pull_request") {
			_, err = parsePullRequestArgs([]byte(raw))
		} else {
			_, err = parseBranchArgs([]byte(raw))
		}
		if !refusedWith(err, contracts.ReasonSchemaViolation) {
			t.Errorf("%s was accepted (%v)", name, err)
		}
	}
	// The limits themselves are accepted.
	if _, err := parseBranchArgs([]byte(branch(`"content_utf8":"a"`, `"content_utf8":"`+big+`"`))); err != nil {
		t.Errorf("content of exactly %d bytes: %v", maxContentBytes, err)
	}
}

func TestTargets(t *testing.T) {
	good := map[string]repository{
		"github.com/Mindburn-Labs/helm-ai-kernel": {"Mindburn-Labs", "helm-ai-kernel"},
		"github.com/a/b.c_d-e":                    {"a", "b.c_d-e"},
	}
	for target, want := range good {
		got, err := parseTarget(target)
		if err != nil || got != want {
			t.Errorf("%s: %+v %v", target, got, err)
		}
	}
	for _, target := range []string{
		"", "github.com/o", "github.com/o/", "github.com/o/r/", "github.com/o/r#x", "github.com/o/r?x",
		"github.com/o/r/pulls", "github.com//r", "github.com/o/..", "github.com/o/.", "github.com/o_x/r",
		"GitHub.com/o/r", "https://github.com/o/r", "github.com/" + strings.Repeat("o", 40) + "/r",
		"github.com/o/r%2Fx", "github.com/o/r x",
	} {
		if _, err := parseTarget(target); !refusedWith(err, contracts.ReasonSchemaViolation) {
			t.Errorf("target %q was accepted (%v)", target, err)
		}
	}
}

// TestGitHubBranchFilesDigestVector is the contract's vector
// (gateway-effect-api.md).
func TestGitHubBranchFilesDigestVector(t *testing.T) {
	files := []fileChange{
		{Path: "scripts/ok.sh", Mode: "100755", Content: "#!/bin/sh\necho ok\n"},
		{Path: "docs/skeleton.md", Mode: "100644", Content: "# Skeleton\n"},
	}
	if got := blobSHA1(files[1].Content); got != "41b86bfc1930f3be282f9d5dcb8b3816deda7b8c" {
		t.Errorf("blob of docs/skeleton.md = %s", got)
	}
	if got := blobSHA1(files[0].Content); got != "e37f89b3b76e73e0d000552c897006f0b8ba1b76" {
		t.Errorf("blob of scripts/ok.sh = %s", got)
	}
	if got := hex.EncodeToString(filesDigest(files)); got != "c361fc7cce27fa9aa3f9e7ef1b275961a2418fff20e16fa1846e5bc50b43ec54" {
		t.Errorf("files_digest = %s", got)
	}
	if blobSHA1("") != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" {
		t.Error("the empty blob is not git's")
	}
}

func TestCheckBranchAttempt(t *testing.T) {
	const tenant, target = "tenant-a", "github.com/o/r"
	view := BranchAttemptView{
		AttemptID: "0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d", TenantID: tenant,
		EffectType: EffectBranchCreateFromChanges, Target: target, State: "OBSERVED", Outcome: "SUCCEEDED",
		Arguments: []byte(validBranch), CommitSHA: "0123456789abcdef0123456789abcdef01234567",
	}
	proposal := PullRequestProposal{TenantID: tenant, Target: target, Arguments: []byte(validPullRequest)}
	if err := CheckBranchAttempt(view, proposal); err != nil {
		t.Fatalf("the matching attempt: %v", err)
	}
	for _, state := range []string{"RECONCILED", "SETTLED"} {
		v := view
		v.State = state
		if err := CheckBranchAttempt(v, proposal); err != nil {
			t.Errorf("%s: %v", state, err)
		}
	}
	for name, mutate := range map[string]func(*BranchAttemptView){
		"other attempt": func(v *BranchAttemptView) { v.AttemptID = "0192f0c4-7a1e-7c3b-9d2a-000000000000" },
		"other tenant":  func(v *BranchAttemptView) { v.TenantID = "tenant-b" },
		"no tenant":     func(v *BranchAttemptView) { v.TenantID = "" },
		"other target":  func(v *BranchAttemptView) { v.Target = "github.com/o/other" },
		"other effect":  func(v *BranchAttemptView) { v.EffectType = EffectPullRequestCreateDraft },
		"failed":        func(v *BranchAttemptView) { v.Outcome = "FAILED" },
		"unknown":       func(v *BranchAttemptView) { v.State, v.Outcome = "UNKNOWN", "" },
		"dispatched":    func(v *BranchAttemptView) { v.State = "DISPATCHED" },
		"other head":    func(v *BranchAttemptView) { v.Arguments = []byte(strings.Replace(validBranch, "helm/x", "helm/y", 1)) },
		"other base": func(v *BranchAttemptView) {
			v.Arguments = []byte(strings.Replace(validBranch, `"base":"main"`, `"base":"dev"`, 1))
		},
		"unreadable":         func(v *BranchAttemptView) { v.Arguments = []byte(`{}`) },
		"other commit":       func(v *BranchAttemptView) { v.CommitSHA = strings.Repeat("f", 40) },
		"no observed commit": func(v *BranchAttemptView) { v.CommitSHA = "" },
	} {
		v := view
		mutate(&v)
		if err := CheckBranchAttempt(v, proposal); !refusedWith(err, contracts.ReasonPreconditionFailed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := proposal
	bad.Arguments = []byte(`{"schema":"helm.github.pull_request.create_draft.v1"}`)
	if err := CheckBranchAttempt(view, bad); !refusedWith(err, contracts.ReasonSchemaViolation) {
		t.Errorf("unreadable pull request arguments: %v", err)
	}
}

// The declarations say what the schemas' x-helm blocks say.
func TestDeclarationsMatchTheSchemas(t *testing.T) {
	for file, effectType := range map[string]string{
		"branch_create_from_changes.v1.json": EffectBranchCreateFromChanges,
		"pull_request_create_draft.v1.json":  EffectPullRequestCreateDraft,
		"repository_get.v1.json":             EffectRepositoryGet,
	} {
		raw, err := os.ReadFile(filepath.Join(schemasDir(t), file))
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			XHelm map[string]string `json:"x-helm"`
		}
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatal(err)
		}
		x := schema.XHelm
		d, ok := declaration(effectType)
		if !ok || x["effect_type"] != effectType {
			t.Fatalf("%s: no declaration for %s", file, x["effect_type"])
		}
		first := func(s string) string { word, _, _ := strings.Cut(s, ":"); return word }
		if string(d.RiskClass) != x["risk_class"] || string(d.Idempotent) != first(x["idempotent"]) ||
			string(d.Observable) != first(x["observable"]) || string(d.Reversible) != first(x["reversible"]) ||
			string(d.Mediation) != x["mediation"] {
			t.Errorf("%s: declaration %+v differs from x-helm %v", effectType, d, x)
		}
	}
	if len(New().Declarations()) != 3 {
		t.Error("the adapter declares other than its three effects")
	}
}

func TestNewRefusesRedirects(t *testing.T) {
	a := New()
	if a.httpClient.CheckRedirect == nil {
		t.Fatal("the adapter's client follows redirects")
	}
	var _ adapters.Adapter = a
}

func TestRepositoryArguments(t *testing.T) {
	for raw, want := range map[string]string{
		`{"schema":"helm.github.repository.get.v1"}`:                      "",
		`{"schema":"helm.github.repository.get.v1","branch":"helm/x"}`:    "helm/x",
		`{"branch":"main","schema":"helm.github.repository.get.v1"}`:      "main",
		`{"schema":"helm.github.repository.get.v1","branch":"a.b/c-d_e"}`: "a.b/c-d_e",
	} {
		got, err := parseRepositoryArgs([]byte(raw))
		if err != nil || got.Branch != want {
			t.Errorf("%s: %+v %v", raw, got, err)
		}
	}
	for _, raw := range []string{
		`{}`,
		`{"schema":"helm.github.repository.get.v2"}`,
		`{"schema":"helm.github.repository.get.v1","branch":null}`,
		`{"schema":"helm.github.repository.get.v1","branch":""}`,
		`{"schema":"helm.github.repository.get.v1","branch":"refs/heads/main"}`,
		`{"schema":"helm.github.repository.get.v1","branch":"a..b"}`,
		`{"schema":"helm.github.repository.get.v1","repo":"o/r"}`,
		`{"schema":"helm.github.repository.get.v1","Branch":"main"}`,
		`{"schema":"helm.github.repository.get.v1","branch":"main","branch":"dev"}`,
		`{"schema":"helm.github.repository.get.v1","pad":"` + strings.Repeat("x", maxReadArgumentBytes) + `"}`,
	} {
		if _, err := parseRepositoryArgs([]byte(raw)); !refusedWith(err, contracts.ReasonSchemaViolation) {
			t.Errorf("%.80s was accepted (%v)", raw, err)
		}
	}
}
