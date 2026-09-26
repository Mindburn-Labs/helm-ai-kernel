package github

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // git object IDs are SHA-1 by definition; this computes them, it does not trust them.
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// The limits of the v1 argument schemas
// (protocols/json-schemas/effects/github/*.v1.json) and of the design note
// (docs/architecture/gateway-effect-api.md, "Typed observation results and
// the GitHub effects"). JSON Schema maxLength counts characters; the byte caps
// are the gateway's.
const (
	maxArgumentBytes = 65536
	// github.repository.get's arguments are at most 4096 bytes.
	maxReadArgumentBytes = 4096
	maxFiles             = 50
	maxPathChars         = 255
	maxContentBytes      = 49152
	maxBodyBytes         = 65536
)

var (
	ownerRE   = regexp.MustCompile(`^[A-Za-z0-9-]{1,39}$`)
	repoRE    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	shaRE     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	headRE    = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	attemptRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// The path schema's "not anyOf", pattern for pattern.
	badPathREs = []*regexp.Regexp{
		regexp.MustCompile(`^/`),
		regexp.MustCompile(`(^|/)\.\.?(/|$)`),
		regexp.MustCompile(`//`),
		regexp.MustCompile(`/$`),
		regexp.MustCompile(`^\.git(/|$)`),
		regexp.MustCompile(`^\.github/workflows(/|$)`),
		regexp.MustCompile(`[\x00-\x1f\\]`),
	}
)

// repository is a validated target.
type repository struct {
	Owner string
	Name  string
}

func (r repository) fullName() string { return r.Owner + "/" + r.Name }

// parseTarget accepts exactly github.com/{owner}/{repo}. Nothing else can
// name the repository (audit 09-02), so a '#', '?', extra segment or trailing
// slash is refused rather than trimmed.
func parseTarget(target string) (repository, error) {
	rest, ok := strings.CutPrefix(target, "github.com/")
	if !ok {
		return repository{}, schemaViolation("target %q is not github.com/{owner}/{repo}", target)
	}
	owner, name, ok := strings.Cut(rest, "/")
	if !ok || !ownerRE.MatchString(owner) || !repoRE.MatchString(name) || name == "." || name == ".." {
		return repository{}, schemaViolation("target %q is not github.com/{owner}/{repo}", target)
	}
	return repository{Owner: owner, Name: name}, nil
}

// fileChange is one file of a branch.
type fileChange struct {
	Path    string
	Mode    string
	Content string
}

// branchArgs is helm.github.branch.create_from_changes.v1.
type branchArgs struct {
	Base    string
	BaseSHA string
	Head    string
	Message string
	Files   []fileChange
}

// pullRequestArgs is helm.github.pull_request.create_draft.v1.
type pullRequestArgs struct {
	BranchAttemptID string
	Base            string
	Head            string
	HeadSHA         string
	Title           string
	Body            string
}

func schemaViolation(format string, args ...any) *adapters.Refusal {
	return adapters.Refuse(contracts.ReasonSchemaViolation, format, args...)
}

// object is one JSON object whose keys are checked exactly. encoding/json
// matches struct fields case-insensitively, so the closed schemas are
// enforced on a map of raw values instead.
type object map[string]json.RawMessage

// decodeObject checks the document rules the schemas state in prose (UTF-8,
// size, no duplicate key at any depth) and returns the top-level object.
func decodeObject(raw []byte) (object, error) {
	if len(raw) > maxArgumentBytes {
		return nil, schemaViolation("arguments are %d bytes, more than %d", len(raw), maxArgumentBytes)
	}
	if !utf8.Valid(raw) {
		return nil, schemaViolation("arguments are not UTF-8")
	}
	if err := checkNoDuplicateKeys(raw); err != nil {
		return nil, err
	}
	var obj object
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, schemaViolation("arguments are not one JSON object")
	}
	return obj, nil
}

// fields checks the object has exactly the required keys.
func (o object) fields(where string, required ...string) error {
	if len(o) != len(required) {
		return schemaViolation("%s has fields %v, want exactly %v", where, keys(o), required)
	}
	for _, name := range required {
		if _, ok := o[name]; !ok {
			return schemaViolation("%s has fields %v, want exactly %v", where, keys(o), required)
		}
	}
	return nil
}

func keys(o object) []string {
	out := make([]string, 0, len(o))
	for k := range o {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// str decodes a string field and applies its character bounds.
func (o object) str(name string, minChars, maxChars int) (string, error) {
	var s string
	// null would decode to "" without an error.
	if value := bytes.TrimSpace(o[name]); len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &s) != nil {
		return "", schemaViolation("%s is not a string", name)
	}
	// encoding/json substitutes U+FFFD for a lone surrogate escape, so the
	// decoded text would differ from the bytes the approver saw.
	if strings.ContainsRune(s, utf8.RuneError) {
		return "", schemaViolation("%s contains U+FFFD or an unpaired surrogate", name)
	}
	if n := utf8.RuneCountInString(s); n < minChars || n > maxChars {
		return "", schemaViolation("%s has %d characters, want %d to %d", name, n, minChars, maxChars)
	}
	return s, nil
}

func (o object) match(name string, re *regexp.Regexp, maxChars int) (string, error) {
	s, err := o.str(name, 1, maxChars)
	if err != nil {
		return "", err
	}
	if !re.MatchString(s) {
		return "", schemaViolation("%s %q does not match %s", name, s, re)
	}
	return s, nil
}

func (o object) schemaConst(want string) error {
	s, err := o.str("schema", 1, 200)
	if err != nil || s != want {
		return schemaViolation("schema is not %q", want)
	}
	return nil
}

// headName applies the schema pattern and git check-ref-format to the head.
func (o object) headName() (string, error) { return o.branchName("head") }

// branchName applies the schema pattern and git check-ref-format to a branch
// name field.
func (o object) branchName(field string) (string, error) {
	head, err := o.match(field, headRE, 200)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(head, "refs/") || strings.HasPrefix(head, "-") || strings.HasPrefix(head, "/") ||
		strings.HasSuffix(head, "/") || strings.HasSuffix(head, ".") || strings.Contains(head, "//") ||
		strings.Contains(head, "..") {
		return "", schemaViolation("%s %q is not a valid branch name", field, head)
	}
	for _, part := range strings.Split(head, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return "", schemaViolation("%s %q is not a valid branch name", field, head)
		}
	}
	return head, nil
}

func parseBranchArgs(raw []byte) (branchArgs, error) {
	obj, err := decodeObject(raw)
	if err != nil {
		return branchArgs{}, err
	}
	if err := obj.fields("arguments", "schema", "base", "base_sha", "head", "message", "files"); err != nil {
		return branchArgs{}, err
	}
	if err := obj.schemaConst("helm.github.branch.create_from_changes.v1"); err != nil {
		return branchArgs{}, err
	}
	var a branchArgs
	if a.Base, err = obj.str("base", 1, 200); err != nil {
		return branchArgs{}, err
	}
	if a.BaseSHA, err = obj.match("base_sha", shaRE, 40); err != nil {
		return branchArgs{}, err
	}
	if a.Head, err = obj.headName(); err != nil {
		return branchArgs{}, err
	}
	if a.Message, err = obj.str("message", 1, 1000); err != nil {
		return branchArgs{}, err
	}
	var items []object
	if err := json.Unmarshal(obj["files"], &items); err != nil {
		return branchArgs{}, schemaViolation("files is not an array of objects")
	}
	if len(items) < 1 || len(items) > maxFiles {
		return branchArgs{}, schemaViolation("files has %d items, want 1 to %d", len(items), maxFiles)
	}
	seen := map[string]bool{}
	for i, item := range items {
		if item == nil {
			return branchArgs{}, schemaViolation("files[%d] is not an object", i)
		}
		if err := item.fields(fmt.Sprintf("files[%d]", i), "path", "mode", "content_utf8"); err != nil {
			return branchArgs{}, err
		}
		var f fileChange
		if f.Path, err = item.str("path", 1, maxPathChars); err != nil {
			return branchArgs{}, err
		}
		for _, re := range badPathREs {
			if re.MatchString(f.Path) {
				return branchArgs{}, schemaViolation("files[%d].path %q is refused (%s)", i, f.Path, re)
			}
		}
		if !norm.NFC.IsNormalString(f.Path) {
			return branchArgs{}, schemaViolation("files[%d].path %q is not NFC", i, f.Path)
		}
		if seen[f.Path] {
			return branchArgs{}, schemaViolation("files[%d].path %q is repeated", i, f.Path)
		}
		seen[f.Path] = true
		if f.Mode, err = item.str("mode", 1, 6); err != nil {
			return branchArgs{}, err
		}
		if f.Mode != "100644" && f.Mode != "100755" {
			return branchArgs{}, schemaViolation("files[%d].mode %q is not 100644 or 100755", i, f.Mode)
		}
		if f.Content, err = item.str("content_utf8", 0, maxContentBytes); err != nil {
			return branchArgs{}, err
		}
		if len(f.Content) > maxContentBytes {
			return branchArgs{}, schemaViolation("files[%d].content_utf8 is %d bytes, more than %d", i, len(f.Content), maxContentBytes)
		}
		a.Files = append(a.Files, f)
	}
	return a, nil
}

func parsePullRequestArgs(raw []byte) (pullRequestArgs, error) {
	obj, err := decodeObject(raw)
	if err != nil {
		return pullRequestArgs{}, err
	}
	if err := obj.fields("arguments", "schema", "branch_attempt_id", "base", "head", "head_sha", "title", "body"); err != nil {
		return pullRequestArgs{}, err
	}
	if err := obj.schemaConst("helm.github.pull_request.create_draft.v1"); err != nil {
		return pullRequestArgs{}, err
	}
	var a pullRequestArgs
	if a.BranchAttemptID, err = obj.match("branch_attempt_id", attemptRE, 36); err != nil {
		return pullRequestArgs{}, err
	}
	if a.Base, err = obj.str("base", 1, 200); err != nil {
		return pullRequestArgs{}, err
	}
	if a.Head, err = obj.headName(); err != nil {
		return pullRequestArgs{}, err
	}
	if a.HeadSHA, err = obj.match("head_sha", shaRE, 40); err != nil {
		return pullRequestArgs{}, err
	}
	if a.Title, err = obj.str("title", 1, 256); err != nil {
		return pullRequestArgs{}, err
	}
	if a.Body, err = obj.str("body", 0, maxBodyBytes); err != nil {
		return pullRequestArgs{}, err
	}
	if len(a.Body) > maxBodyBytes {
		return pullRequestArgs{}, schemaViolation("body is %d bytes, more than %d", len(a.Body), maxBodyBytes)
	}
	return a, nil
}

// repositoryArgs is helm.github.repository.get.v1. Branch is empty when the
// effect asks only for the default branch.
type repositoryArgs struct {
	Branch string
}

func parseRepositoryArgs(raw []byte) (repositoryArgs, error) {
	if len(raw) > maxReadArgumentBytes {
		return repositoryArgs{}, schemaViolation("arguments are %d bytes, more than %d", len(raw), maxReadArgumentBytes)
	}
	obj, err := decodeObject(raw)
	if err != nil {
		return repositoryArgs{}, err
	}
	required := []string{"schema"}
	if _, ok := obj["branch"]; ok {
		required = append(required, "branch")
	}
	if err := obj.fields("arguments", required...); err != nil {
		return repositoryArgs{}, schemaViolation("arguments have fields %v, want schema and an optional branch", keys(obj))
	}
	if err := obj.schemaConst("helm.github.repository.get.v1"); err != nil {
		return repositoryArgs{}, err
	}
	var a repositoryArgs
	if len(required) == 2 {
		if a.Branch, err = obj.branchName("branch"); err != nil {
			return repositoryArgs{}, err
		}
	}
	return a, nil
}

// checkNoDuplicateKeys walks the document and refuses any object that
// repeats a key, at any depth. encoding/json would keep the last one.
func checkNoDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walkValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return schemaViolation("arguments have content after the JSON value")
	}
	return nil
}

func walkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return schemaViolation("arguments are not valid JSON")
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return schemaViolation("arguments are not valid JSON")
			}
			key, _ := keyTok.(string)
			if seen[key] {
				return schemaViolation("duplicate key %q", key)
			}
			seen[key] = true
			if err := walkValue(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkValue(dec); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil { // the closing delimiter
		return schemaViolation("arguments are not valid JSON")
	}
	return nil
}

// blobSHA1 is git's object ID of a blob: sha1("blob <len>\0" + bytes).
func blobSHA1(content string) string {
	h := sha1.New() //nolint:gosec // see the import
	fmt.Fprintf(h, "blob %d\x00", len(content))
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

// filesDigest is GitHubBranchResult.files_digest: SHA-256 over the files
// sorted by path, each encoded as path 0x00 mode 0x00 blob-sha1-hex 0x0A.
func filesDigest(files []fileChange) []byte {
	sorted := append([]fileChange(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	h := sha256.New()
	for _, f := range sorted {
		fmt.Fprintf(h, "%s\x00%s\x00%s\n", f.Path, f.Mode, blobSHA1(f.Content))
	}
	return h.Sum(nil)
}

// BranchAttemptView is what the gateway knows at Propose about the branch
// attempt a draft pull request names.
type BranchAttemptView struct {
	AttemptID  string
	TenantID   string
	EffectType string
	Target     string
	// State is the attempt's EffectAttemptState name without its prefix,
	// for example "OBSERVED".
	State string
	// Outcome is "SUCCEEDED", "FAILED" or empty.
	Outcome string
	// Arguments are the branch attempt's retained argument bytes.
	Arguments []byte
	// CommitSHA is the commit_sha of its SUCCEEDED GitHubBranchResult.
	CommitSHA string
}

// PullRequestProposal is the draft pull request being proposed.
type PullRequestProposal struct {
	TenantID  string
	Target    string
	Arguments []byte
}

// CheckBranchAttempt is the draft pull request's Propose precondition
// (gateway-effect-api.md): the named branch attempt is in the same tenant and
// target, is github.branch.create_from_changes observed to succeed, has the
// same head and base, and its commit is head_sha. It returns a *Refusal with
// PRECONDITION_FAILED, or SCHEMA_VIOLATION for unreadable arguments. The
// gateway calls it; it does no I/O.
func CheckBranchAttempt(branch BranchAttemptView, pr PullRequestProposal) error {
	prArgs, err := parsePullRequestArgs(pr.Arguments)
	if err != nil {
		return err
	}
	failed := func(why string) error {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "branch_attempt_id %s: %s", prArgs.BranchAttemptID, why)
	}
	switch {
	case branch.AttemptID != prArgs.BranchAttemptID:
		return failed("the view is of another attempt")
	case branch.TenantID == "" || branch.TenantID != pr.TenantID:
		return failed("not an attempt of this tenant")
	case branch.EffectType != EffectBranchCreateFromChanges || branch.Target != pr.Target:
		return failed("not a branch of this repository")
	case branch.Outcome != "SUCCEEDED" || (branch.State != "OBSERVED" && branch.State != "RECONCILED" && branch.State != "SETTLED"):
		return failed("the branch attempt has not been observed to succeed")
	}
	branchArgs, err := parseBranchArgs(branch.Arguments)
	if err != nil {
		return failed("the branch attempt's arguments are unreadable")
	}
	if branchArgs.Head != prArgs.Head || branchArgs.Base != prArgs.Base {
		return failed("head and base differ from the branch attempt's")
	}
	if branch.CommitSHA == "" || branch.CommitSHA != prArgs.HeadSHA {
		return failed("head_sha is not the branch attempt's observed commit")
	}
	return nil
}
