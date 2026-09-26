// Package effectargs checks an effect's argument bytes before admission.
//
// Every effect's arguments are one JSON object of at most MaxBytes of UTF-8,
// with no duplicate key at any depth. The effect types of the HELM-789
// walking skeleton also have closed schemas (HELM-753,
// protocols/json-schemas/effects/github/*.v1.json): unknown or missing fields,
// wrong types and out-of-range values are refused, and so are the rules the
// schemas state in prose (NFC paths, git ref format, content size). The
// gateway digests the bytes as sent; this package only accepts or refuses
// them, and returns the parsed object a mandate condition reads as
// input.args.
package effectargs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// MaxBytes bounds any effect's arguments.
const MaxBytes = 65536

// The skeleton's effect types.
const (
	GitHubBranchCreateFromChanges = "github.branch.create_from_changes"
	GitHubPullRequestCreateDraft  = "github.pull_request.create_draft"
	GitHubRepositoryGet           = "github.repository.get"
)

// maxRepositoryGetBytes caps github.repository.get's arguments.
const maxRepositoryGetBytes = 4096

// ErrInvalid wraps every refusal.
var ErrInvalid = errors.New("effect arguments are invalid")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Validate checks raw as the arguments of effectType on target and returns the
// parsed object.
func Validate(effectType, target string, raw []byte) (map[string]any, error) {
	if len(raw) > MaxBytes {
		return nil, invalid("arguments are %d bytes, more than %d", len(raw), MaxBytes)
	}
	if !utf8.Valid(raw) {
		return nil, invalid("arguments are not UTF-8")
	}
	if err := checkNoDuplicateKeys(raw); err != nil {
		return nil, err
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed == nil {
		return nil, invalid("arguments are not one JSON object")
	}
	switch effectType {
	case GitHubBranchCreateFromChanges:
		if err := checkGitHubTarget(target); err != nil {
			return nil, err
		}
		var args BranchCreateFromChanges
		if err := requireExactKeys(raw, "schema", "base", "base_sha", "head", "message", "files"); err != nil {
			return nil, err
		}
		if err := requireExactFileKeys(raw); err != nil {
			return nil, err
		}
		if err := strictDecode(raw, &args); err != nil {
			return nil, err
		}
		if err := args.validate(); err != nil {
			return nil, err
		}
	case GitHubRepositoryGet:
		if len(raw) > maxRepositoryGetBytes {
			return nil, invalid("arguments are %d bytes, more than %d", len(raw), maxRepositoryGetBytes)
		}
		if err := checkGitHubTarget(target); err != nil {
			return nil, err
		}
		var args RepositoryGet
		if err := requireExactKeys(raw, "schema", "branch"); err != nil {
			return nil, err
		}
		if err := strictDecode(raw, &args); err != nil {
			return nil, err
		}
		if err := constant("schema", args.Schema, "helm.github.repository.get.v1"); err != nil {
			return nil, err
		}
		if args.Branch != nil {
			if err := checkHead(args.Branch); err != nil {
				return nil, err
			}
		}
	case GitHubPullRequestCreateDraft:
		if err := checkGitHubTarget(target); err != nil {
			return nil, err
		}
		var args PullRequestCreateDraft
		if err := requireExactKeys(raw, "schema", "branch_attempt_id", "base", "head", "head_sha", "title", "body"); err != nil {
			return nil, err
		}
		if err := strictDecode(raw, &args); err != nil {
			return nil, err
		}
		if err := args.validate(); err != nil {
			return nil, err
		}
	}
	return parsed, nil
}

// BranchCreateFromChanges is github.branch.create_from_changes v1.
type BranchCreateFromChanges struct {
	Schema  *string       `json:"schema"`
	Base    *string       `json:"base"`
	BaseSHA *string       `json:"base_sha"`
	Head    *string       `json:"head"`
	Message *string       `json:"message"`
	Files   *[]BranchFile `json:"files"`
}

// BranchFile is one file of a branch change.
type BranchFile struct {
	Path        *string `json:"path"`
	Mode        *string `json:"mode"`
	ContentUTF8 *string `json:"content_utf8"`
}

// RepositoryGet is github.repository.get v1, a read.
type RepositoryGet struct {
	Schema *string `json:"schema"`
	Branch *string `json:"branch"`
}

// PullRequestCreateDraft is github.pull_request.create_draft v1.
type PullRequestCreateDraft struct {
	Schema          *string `json:"schema"`
	BranchAttemptID *string `json:"branch_attempt_id"`
	Base            *string `json:"base"`
	Head            *string `json:"head"`
	HeadSHA         *string `json:"head_sha"`
	Title           *string `json:"title"`
	Body            *string `json:"body"`
}

var (
	gitHubTargetPattern = regexp.MustCompile(`^github\.com/[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$`)
	shaPattern          = regexp.MustCompile(`^[0-9a-f]{40}$`)
	headPattern         = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	uuidPattern         = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// maxContentBytes caps one file's content (the schema's 49152 characters,
// also as bytes).
const maxContentBytes = 49152

func (a BranchCreateFromChanges) validate() error {
	if err := constant("schema", a.Schema, "helm.github.branch.create_from_changes.v1"); err != nil {
		return err
	}
	if err := length("base", a.Base, 1, 200); err != nil {
		return err
	}
	if err := match("base_sha", a.BaseSHA, shaPattern); err != nil {
		return err
	}
	if err := checkHead(a.Head); err != nil {
		return err
	}
	if err := length("message", a.Message, 1, 1000); err != nil {
		return err
	}
	if a.Files == nil {
		return invalid("files is required")
	}
	if n := len(*a.Files); n < 1 || n > 50 {
		return invalid("files has %d entries, want 1 to 50", n)
	}
	paths := make(map[string]struct{}, len(*a.Files))
	for i, f := range *a.Files {
		if f.Path == nil || f.Mode == nil || f.ContentUTF8 == nil {
			return invalid("files[%d] needs path, mode and content_utf8", i)
		}
		if err := checkPath(*f.Path); err != nil {
			return invalid("files[%d].path: %v", i, err)
		}
		if _, dup := paths[*f.Path]; dup {
			return invalid("files[%d].path %q repeats", i, *f.Path)
		}
		paths[*f.Path] = struct{}{}
		if *f.Mode != "100644" && *f.Mode != "100755" {
			return invalid("files[%d].mode %q is not 100644 or 100755", i, *f.Mode)
		}
		if len(*f.ContentUTF8) > maxContentBytes {
			return invalid("files[%d].content_utf8 is more than %d bytes", i, maxContentBytes)
		}
	}
	return nil
}

func (a PullRequestCreateDraft) validate() error {
	if err := constant("schema", a.Schema, "helm.github.pull_request.create_draft.v1"); err != nil {
		return err
	}
	if err := match("branch_attempt_id", a.BranchAttemptID, uuidPattern); err != nil {
		return err
	}
	if err := length("base", a.Base, 1, 200); err != nil {
		return err
	}
	if err := checkHead(a.Head); err != nil {
		return err
	}
	if err := match("head_sha", a.HeadSHA, shaPattern); err != nil {
		return err
	}
	if err := length("title", a.Title, 1, 256); err != nil {
		return err
	}
	return length("body", a.Body, 0, 65536)
}

// checkGitHubTarget: github.com/{owner}/{repo}, nothing else.
func checkGitHubTarget(target string) error {
	if !gitHubTargetPattern.MatchString(target) {
		return invalid("target %q is not github.com/{owner}/{repo}", target)
	}
	if repo := target[strings.LastIndex(target, "/")+1:]; repo == "." || repo == ".." {
		return invalid("target %q names no repository", target)
	}
	return nil
}

// checkHead applies the schema pattern and git check-ref-format's rules for a
// branch name (head, or github.repository.get's branch).
func checkHead(head *string) error {
	if err := length("head", head, 1, 200); err != nil {
		return err
	}
	h := *head
	switch {
	case !headPattern.MatchString(h), strings.HasPrefix(h, "refs/"):
		return invalid("head %q is not a branch name", h)
	case strings.HasPrefix(h, "/"), strings.HasSuffix(h, "/"), strings.Contains(h, "//"),
		strings.Contains(h, ".."), strings.HasSuffix(h, "."), h == "@":
		return invalid("head %q fails git check-ref-format", h)
	}
	for _, component := range strings.Split(h, "/") {
		if strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".lock") {
			return invalid("head %q fails git check-ref-format", h)
		}
	}
	return nil
}

// checkPath refuses absolute, empty-segment, '.', '..', .git, workflow and
// control-character paths, and paths that are not NFC.
func checkPath(p string) error {
	switch {
	case p == "" || len(p) > 255:
		return errors.New("length out of range")
	case !norm.NFC.IsNormalString(p):
		return errors.New("not NFC")
	case strings.HasPrefix(p, "/"), strings.HasSuffix(p, "/"), strings.Contains(p, "//"):
		return errors.New("empty segment")
	case strings.ContainsAny(p, "\\") || strings.IndexFunc(p, func(r rune) bool { return r < 0x20 }) >= 0:
		return errors.New("control character or backslash")
	case p == ".git" || strings.HasPrefix(p, ".git/"):
		return errors.New("inside .git")
	case p == ".github/workflows" || strings.HasPrefix(p, ".github/workflows/"):
		return errors.New("a workflow file is code execution and needs its own effect type")
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "." || segment == ".." {
			return errors.New("'.' or '..' segment")
		}
	}
	return nil
}

func constant(name string, v *string, want string) error {
	if v == nil || *v != want {
		return invalid("%s must be %q", name, want)
	}
	return nil
}

// length counts characters, as JSON Schema's minLength and maxLength do.
func length(name string, v *string, lo, hi int) error {
	if v == nil {
		return invalid("%s is required", name)
	}
	if n := utf8.RuneCountInString(*v); n < lo || n > hi {
		return invalid("%s has %d characters, want %d to %d", name, n, lo, hi)
	}
	return nil
}

func match(name string, v *string, pattern *regexp.Regexp) error {
	if v == nil {
		return invalid("%s is required", name)
	}
	if !pattern.MatchString(*v) {
		return invalid("%s %q does not match %s", name, *v, pattern)
	}
	return nil
}

// requireExactKeys refuses any key of the object in raw that is not, byte for
// byte, one of allowed. encoding/json matches struct fields
// case-insensitively (with Unicode folding: "Head", "HEAD" and "ſchema" all
// match), so without this a document could carry "head" for the condition's
// map and "Head" for the typed struct. Duplicate keys are refused earlier, so
// after this check every key names exactly one field.
func requireExactKeys(raw []byte, allowed ...string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return invalid("arguments are not one JSON object")
	}
	return exactKeys(object, allowed, "")
}

// requireExactFileKeys applies the exact-key rule to each entry of files.
func requireExactFileKeys(raw []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return invalid("arguments are not one JSON object")
	}
	var files []map[string]json.RawMessage
	if err := json.Unmarshal(object["files"], &files); err != nil {
		return invalid("files is not a list of objects")
	}
	for i, file := range files {
		if err := exactKeys(file, []string{"path", "mode", "content_utf8"}, fmt.Sprintf("files[%d].", i)); err != nil {
			return err
		}
	}
	return nil
}

func exactKeys(object map[string]json.RawMessage, allowed []string, prefix string) error {
	for key := range object {
		if !slices.Contains(allowed, key) {
			return invalid("unknown field %s%q (field names are exact and case-sensitive)", prefix, key)
		}
	}
	return nil
}

// strictDecode refuses unknown fields and trailing data. Callers check exact
// keys first (requireExactKeys): this decoder alone would fold case.
func strictDecode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("%v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return invalid("trailing data after the arguments")
	}
	return nil
}

// checkNoDuplicateKeys walks the token stream and refuses any object with a
// repeated key, which encoding/json would otherwise resolve silently.
func checkNoDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walk(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return invalid("trailing data after the arguments")
	}
	return nil
}

func walk(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return invalid("not JSON: %v", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]struct{}{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return invalid("not JSON: %v", err)
			}
			key, _ := keyTok.(string)
			if _, dup := keys[key]; dup {
				return invalid("duplicate key %q", key)
			}
			keys[key] = struct{}{}
			if err := walk(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walk(dec); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil { // the closing delimiter
		return invalid("not JSON: %v", err)
	}
	return nil
}
