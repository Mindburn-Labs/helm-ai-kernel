// Package testkit provides the single in-process GitHub API double for
// adapter and gateway conformance. It has no external credentials or I/O.
package testkit

import (
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // git object IDs
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// GitHub is an httptest GitHub that models the endpoints the adapter
// uses, with git's content addressing for blobs: a blob's ID is its real
// SHA-1, so the adapter's blob checks are exercised for real. Trees and
// commits get stable made-up IDs, and every commit is unique, as on GitHub,
// where the commit time is part of the ID.
type GitHub struct {
	t      testing.TB
	owner  string
	name   string
	token  string
	server *httptest.Server

	mu            sync.Mutex
	blobs         map[string]string
	trees         map[string]map[string]fakeEntry
	commits       map[string]fakeCommit
	refs          map[string]string // "heads/x" -> commit
	pulls         []*PullRequest
	seq           int
	mergeMode     string
	mergeRequests int
	pushRequests  int
	refWrites     map[string]int
	pullWrites    map[string]int
	refReads      map[string]int
	pullReads     map[string]int
	mergeReads    int
	dropRef       bool
	dropPull      bool
	branchMode    ReadbackMode
	pullMode      ReadbackMode
}

// FakeGitHub is the reconciliation suite's name for the shared adapter fake.
type FakeGitHub = GitHub

// ReadbackMode controls visibility while preserving applied provider state.
type ReadbackMode string

const (
	ReadbackNormal       ReadbackMode = "normal"
	ReadbackAbsent       ReadbackMode = "absent"
	ReadbackMismatch     ReadbackMode = "mismatch"
	ReadbackInconclusive ReadbackMode = "inconclusive"
)

type fakeEntry struct{ Mode, Blob string }

type fakeCommit struct {
	Tree    string
	Parents []string
	Message string
}

type PullRequest struct {
	Number         int64
	Title          string
	Body           string
	Head, Base     string
	HeadSHA        string
	Draft          bool
	State          string
	Merged         bool
	MergeCommitSHA string
	Stack          json.RawMessage
	HeadRepository string
	BaseRepository string
}

func New(t testing.TB) *GitHub {
	return newGitHub(t, "mindburn-qual", "sandbox")
}

func NewFakeGitHub(t *testing.T) *GitHub { return newGitHub(t, "mindburn-qual", "sandbox") }

func NewFakeGitHubFor(t *testing.T, owner, name string) *GitHub {
	return newGitHub(t, owner, name)
}

func newGitHub(t testing.TB, owner, name string) *GitHub {
	var tokenBytes [16]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		t.Fatalf("fake GitHub: generate token: %v", err)
	}
	f := &GitHub{
		t: t, owner: owner, name: name, token: hex.EncodeToString(tokenBytes[:]), mergeMode: "enqueued",
		blobs: map[string]string{}, trees: map[string]map[string]fakeEntry{},
		commits: map[string]fakeCommit{}, refs: map[string]string{},
		refWrites: map[string]int{}, pullWrites: map[string]int{},
		refReads: map[string]int{}, pullReads: map[string]int{},
	}
	readme := "# sandbox\n"
	f.blobs[blobSHA1(readme)] = readme
	tree := f.putTree(map[string]fakeEntry{"README.md": {Mode: "100644", Blob: blobSHA1(readme)}})
	f.refs["heads/main"] = f.putCommit(fakeCommit{Tree: tree, Message: "initial"})
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func fakeID(parts ...string) string {
	data := ""
	if len(parts) > 0 {
		data = strings.Join(parts, "\x00") + "\x00"
	}
	sum := sha1.Sum([]byte(data)) //nolint:gosec // made-up object IDs
	return hex.EncodeToString(sum[:])
}

func (f *GitHub) putTree(entries map[string]fakeEntry) string {
	paths := make([]string, 0, len(entries))
	for p := range entries {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	parts := []string{"tree"}
	for _, p := range paths {
		parts = append(parts, p, entries[p].Mode, entries[p].Blob)
	}
	id := fakeID(parts...)
	f.trees[id] = entries
	return id
}

func (f *GitHub) putCommit(c fakeCommit) string {
	f.seq++
	id := fakeID(append([]string{"commit", c.Tree, c.Message, fmt.Sprint(f.seq)}, c.Parents...)...)
	f.commits[id] = c
	return id
}

func (f *GitHub) write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		f.t.Errorf("fake GitHub: encode: %v", err)
	}
}

func (f *GitHub) fail(w http.ResponseWriter, status int, msg string) {
	f.write(w, status, map[string]string{"message": msg, "documentation_url": "https://docs.github.com/rest"})
}

func (f *GitHub) repoJSON() map[string]any {
	return map[string]any{
		"id": 1, "node_id": "R_kgDOfake", "name": f.name, "full_name": f.owner + "/" + f.name,
		"private": true, "default_branch": "main", "visibility": "private",
		"owner":       map[string]any{"login": f.owner, "type": "Organization"},
		"permissions": map[string]bool{"admin": false, "push": true, "pull": true},
	}
}

func (f *GitHub) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		f.fail(w, http.StatusUnauthorized, "Bad credentials")
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/graphql" {
		f.updateRefs(w, r)
		return
	}
	prefix := "/repos/" + f.owner + "/" + f.name
	rest, ok := strings.CutPrefix(r.URL.Path, prefix)
	if !ok {
		f.fail(w, http.StatusNotFound, "Not Found")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var body map[string]any
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.fail(w, http.StatusBadRequest, "Problems parsing JSON")
			return
		}
	}
	switch {
	case r.Method == http.MethodGet && rest == "":
		f.write(w, http.StatusOK, f.repoJSON())
	case r.Method == http.MethodGet && strings.HasPrefix(rest, "/git/ref/"):
		name := strings.TrimPrefix(rest, "/git/ref/")
		f.refReads[name]++
		if name != "heads/main" {
			switch f.branchMode {
			case ReadbackAbsent:
				f.fail(w, http.StatusNotFound, "Not Found")
				return
			case ReadbackInconclusive:
				f.fail(w, http.StatusServiceUnavailable, "Read-back unavailable")
				return
			}
		}
		sha, ok := f.refs[name]
		if !ok {
			f.fail(w, http.StatusNotFound, "Not Found")
			return
		}
		f.write(w, http.StatusOK, f.refJSON(name, sha))
	case r.Method == http.MethodGet && strings.HasPrefix(rest, "/git/commits/"):
		sha := strings.TrimPrefix(rest, "/git/commits/")
		c, ok := f.commits[sha]
		if !ok {
			f.fail(w, http.StatusNotFound, "Not Found")
			return
		}
		answer := f.commitJSON(sha, c)
		if f.branchMode == ReadbackMismatch && sha != f.refs["heads/main"] {
			answer["parents"] = []map[string]string{{"sha": strings.Repeat("f", 40)}}
		}
		f.write(w, http.StatusOK, answer)
	case r.Method == http.MethodPost && rest == "/git/blobs":
		content, _ := body["content"].(string)
		sha := blobSHA1(content)
		f.blobs[sha] = content
		f.write(w, http.StatusCreated, map[string]string{"sha": sha, "url": f.server.URL + prefix + "/git/blobs/" + sha})
	case r.Method == http.MethodPost && rest == "/git/trees":
		f.createTree(w, body)
	case r.Method == http.MethodPost && rest == "/git/commits":
		f.createCommit(w, body)
	case r.Method == http.MethodPost && rest == "/git/refs":
		ref, _ := body["ref"].(string)
		sha, _ := body["sha"].(string)
		name, ok := strings.CutPrefix(ref, "refs/")
		switch {
		case !ok:
			f.fail(w, http.StatusUnprocessableEntity, "Reference name is invalid")
		case f.refs[name] != "":
			f.fail(w, http.StatusUnprocessableEntity, "Reference already exists")
		case f.commits[sha].Tree == "":
			f.fail(w, http.StatusUnprocessableEntity, "Object does not exist")
		default:
			f.refs[name] = sha
			f.refWrites[name]++
			if f.dropRef {
				dropAnswer(w)
				return
			}
			f.write(w, http.StatusCreated, f.refJSON(name, sha))
		}
	case r.Method == http.MethodGet && strings.HasPrefix(rest, "/compare/"):
		f.compare(w, strings.TrimPrefix(rest, "/compare/"))
	case r.Method == http.MethodGet && rest == "/events":
		w.Header().Set("X-Poll-Interval", "60")
		f.write(w, http.StatusOK, []any{})
	case r.Method == http.MethodGet && strings.HasPrefix(rest, "/pulls/"):
		f.getPull(w, strings.TrimPrefix(rest, "/pulls/"))
	case r.Method == http.MethodPut && strings.HasPrefix(rest, "/pulls/") && strings.HasSuffix(rest, "/merge-async"):
		f.mergePull(w, r, strings.TrimSuffix(strings.TrimPrefix(rest, "/pulls/"), "/merge-async"), body)
	case r.Method == http.MethodGet && rest == "/pulls":
		f.listPulls(w, r)
	case r.Method == http.MethodPost && rest == "/pulls":
		f.createPull(w, body)
	default:
		f.fail(w, http.StatusNotFound, "Not Found")
	}
}

func (f *GitHub) updateRefs(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Query     string `json:"query"`
		Variables struct {
			Input struct {
				ClientMutationID string `json:"clientMutationId"`
				RepositoryID     string `json:"repositoryId"`
				RefUpdates       []struct {
					Name      string `json:"name"`
					BeforeOid string `json:"beforeOid"`
					AfterOid  string `json:"afterOid"`
					Force     bool   `json:"force"`
				} `json:"refUpdates"`
			} `json:"input"`
		} `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		f.fail(w, http.StatusBadRequest, "Problems parsing JSON")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushRequests++
	input := request.Variables.Input
	if !strings.Contains(request.Query, "updateRefs") || input.RepositoryID != "R_kgDOfake" || len(input.RefUpdates) != 1 {
		f.write(w, http.StatusOK, map[string]any{"errors": []map[string]string{{"message": "invalid updateRefs input"}}})
		return
	}
	update := input.RefUpdates[0]
	name, validName := strings.CutPrefix(update.Name, "refs/")
	old, exists := f.refs[name]
	commit, validCommit := f.commits[update.AfterOid]
	if !validName || !exists || !validCommit || update.Force || old != update.BeforeOid || len(commit.Parents) != 1 || commit.Parents[0] != old {
		f.write(w, http.StatusOK, map[string]any{"errors": []map[string]string{{"message": "beforeOid mismatch or non-fast-forward update"}}})
		return
	}
	f.refs[name] = update.AfterOid
	f.refWrites[name]++
	if f.dropRef {
		dropAnswer(w)
		return
	}
	f.write(w, http.StatusOK, map[string]any{"data": map[string]any{"updateRefs": map[string]string{"clientMutationId": input.ClientMutationID}}})
}

func (f *GitHub) refJSON(name, sha string) map[string]any {
	return map[string]any{
		"ref": "refs/" + name, "node_id": "REF_fake",
		"url":    f.server.URL + "/repos/" + f.owner + "/" + f.name + "/git/refs/" + name,
		"object": map[string]string{"sha": sha, "type": "commit"},
	}
}

func (f *GitHub) commitJSON(sha string, c fakeCommit) map[string]any {
	parents := []map[string]string{}
	for _, p := range c.Parents {
		parents = append(parents, map[string]string{"sha": p})
	}
	return map[string]any{
		"sha": sha, "node_id": "C_fake", "message": c.Message,
		"author":       map[string]string{"name": "helm-gateway[bot]", "date": "2026-09-26T12:00:00Z"},
		"tree":         map[string]string{"sha": c.Tree},
		"parents":      parents,
		"verification": map[string]any{"verified": false, "reason": "unsigned"},
	}
}

func (f *GitHub) createTree(w http.ResponseWriter, body map[string]any) {
	baseTree, _ := body["base_tree"].(string)
	base, ok := f.trees[baseTree]
	if !ok {
		f.fail(w, http.StatusUnprocessableEntity, "base_tree is not a tree")
		return
	}
	entries := map[string]fakeEntry{}
	for p, e := range base {
		entries[p] = e
	}
	items, _ := body["tree"].([]any)
	for _, item := range items {
		e, _ := item.(map[string]any)
		path, _ := e["path"].(string)
		mode, _ := e["mode"].(string)
		sha, _ := e["sha"].(string)
		if _, ok := f.blobs[sha]; !ok || e["type"] != "blob" {
			f.fail(w, http.StatusUnprocessableEntity, "tree.sha is not a blob")
			return
		}
		entries[path] = fakeEntry{Mode: mode, Blob: sha}
	}
	f.write(w, http.StatusCreated, map[string]any{"sha": f.putTree(entries), "truncated": false})
}

func (f *GitHub) createCommit(w http.ResponseWriter, body map[string]any) {
	tree, _ := body["tree"].(string)
	message, _ := body["message"].(string)
	if _, ok := f.trees[tree]; !ok {
		f.fail(w, http.StatusUnprocessableEntity, "Tree SHA does not exist")
		return
	}
	var parents []string
	raw, _ := body["parents"].([]any)
	for _, p := range raw {
		sha, _ := p.(string)
		if _, ok := f.commits[sha]; !ok {
			f.fail(w, http.StatusUnprocessableEntity, "Parent SHA does not exist or is not a commit object")
			return
		}
		parents = append(parents, sha)
	}
	c := fakeCommit{Tree: tree, Parents: parents, Message: message}
	sha := f.putCommit(c)
	f.write(w, http.StatusCreated, f.commitJSON(sha, c))
}

// compare diffs the two commits' trees, as GitHub's three-dot comparison
// does when base is the merge base.
func (f *GitHub) compare(w http.ResponseWriter, spec string) {
	baseSHA, headSHA, ok := strings.Cut(spec, "...")
	base, okBase := f.commits[baseSHA]
	head, okHead := f.commits[headSHA]
	if !ok || !okBase || !okHead {
		f.fail(w, http.StatusNotFound, "Not Found")
		return
	}
	before, after := f.trees[base.Tree], f.trees[head.Tree]
	type file struct {
		SHA       string `json:"sha"`
		Filename  string `json:"filename"`
		Status    string `json:"status"`
		Additions int    `json:"additions"`
		Deletions int    `json:"deletions"`
		Changes   int    `json:"changes"`
		Patch     string `json:"patch"`
	}
	files := []file{}
	for path, e := range after {
		old, existed := before[path]
		switch {
		case !existed:
			files = append(files, file{SHA: e.Blob, Filename: path, Status: "added", Additions: 1, Changes: 1, Patch: "@@ -0,0 +1 @@\n+" + f.blobs[e.Blob]})
		case old.Blob != e.Blob:
			files = append(files, file{SHA: e.Blob, Filename: path, Status: "modified", Additions: 1, Deletions: 1, Changes: 2, Patch: "@@ -1 +1 @@"})
		case old.Mode != e.Mode:
			files = append(files, file{SHA: e.Blob, Filename: path, Status: "changed"})
		}
	}
	for path, e := range before {
		if _, kept := after[path]; !kept {
			files = append(files, file{SHA: e.Blob, Filename: path, Status: "removed", Deletions: 1, Changes: 1})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Filename < files[j].Filename })
	f.write(w, http.StatusOK, map[string]any{
		"status": "ahead", "ahead_by": 1, "behind_by": 0, "total_commits": 1,
		"base_commit":       f.commitJSON(baseSHA, base),
		"merge_base_commit": f.commitJSON(baseSHA, base),
		"commits":           []any{f.commitJSON(headSHA, head)},
		"files":             files,
	})
}

func (f *GitHub) pullJSON(p *PullRequest) map[string]any {
	full := f.owner + "/" + f.name
	headRepo, baseRepo := p.HeadRepository, p.BaseRepository
	if headRepo == "" {
		headRepo = full
	}
	if baseRepo == "" {
		baseRepo = full
	}
	return map[string]any{
		"url":      f.server.URL + "/repos/" + full + "/pulls/" + fmt.Sprint(p.Number),
		"html_url": "https://github.com/" + full + "/pull/" + fmt.Sprint(p.Number),
		"id":       1000 + p.Number, "node_id": fmt.Sprintf("PR_kwDOfake%d", p.Number),
		"number": p.Number, "state": p.State, "title": p.Title, "body": p.Body, "draft": p.Draft,
		"merged": p.Merged, "merge_commit_sha": p.MergeCommitSHA, "stack": p.Stack,
		"locked": false, "user": map[string]string{"login": "helm-gateway[bot]"},
		"head": map[string]any{"label": f.owner + ":" + p.Head, "ref": p.Head, "sha": p.HeadSHA,
			"repo": map[string]any{"full_name": headRepo}},
		"base": map[string]any{"label": f.owner + ":" + p.Base, "ref": p.Base,
			"sha": f.refs["heads/"+p.Base], "repo": map[string]any{"full_name": baseRepo}},
	}
}

func (f *GitHub) listPulls(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if raw := q.Get("head"); raw != "" {
		_, head, _ := strings.Cut(raw, ":")
		f.pullReads[head]++
	}
	if f.pullMode == ReadbackInconclusive {
		f.fail(w, http.StatusServiceUnavailable, "Read-back unavailable")
		return
	}
	if f.pullMode == ReadbackAbsent {
		f.write(w, http.StatusOK, []any{})
		return
	}
	state := q.Get("state")
	if state == "" {
		state = "open"
	}
	out := []map[string]any{}
	for i := len(f.pulls) - 1; i >= 0; i-- { // newest first
		p := f.pulls[i]
		if (q.Get("head") == "" || q.Get("head") == f.owner+":"+p.Head) &&
			(q.Get("base") == "" || q.Get("base") == p.Base) && (state == "all" || state == p.State) {
			answer := f.pullJSON(p)
			if f.pullMode == ReadbackMismatch {
				answer["draft"] = !p.Draft
			}
			out = append(out, answer)
		}
	}
	f.write(w, http.StatusOK, out)
}

func (f *GitHub) createPull(w http.ResponseWriter, body map[string]any) {
	title, _ := body["title"].(string)
	text, _ := body["body"].(string)
	head, _ := body["head"].(string)
	base, _ := body["base"].(string)
	draft, _ := body["draft"].(bool)
	headSHA, okHead := f.refs["heads/"+head]
	if _, okBase := f.refs["heads/"+base]; !okHead || !okBase {
		f.fail(w, http.StatusUnprocessableEntity, "Validation Failed")
		return
	}
	for _, p := range f.pulls {
		if p.Head == head && p.Base == base && p.State == "open" {
			f.fail(w, http.StatusUnprocessableEntity, "A pull request already exists for "+f.owner+":"+head+".")
			return
		}
	}
	p := &PullRequest{Number: int64(len(f.pulls) + 1), Title: title, Body: text, Head: head, Base: base, HeadSHA: headSHA, Draft: draft, State: "open"}
	f.pulls = append(f.pulls, p)
	f.pullWrites[head]++
	if f.dropPull {
		dropAnswer(w)
		return
	}
	f.write(w, http.StatusCreated, f.pullJSON(p))
}

// markReady turns a draft into a ready pull request, as a person would.
func (f *GitHub) MarkReady(number int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.pulls {
		if p.Number == number {
			p.Draft = false
		}
	}
}

// URL returns the local REST server origin.
func (f *GitHub) URL() string { return f.server.URL }

// Name is the fixture repository name.
func (f *GitHub) Name() string { return f.name }

// BaseSHA is the current main branch head.
func (f *GitHub) BaseSHA() string { return f.Head("main") }

// HeadSHA is the current head for a branch.
func (f *GitHub) HeadSHA(head string) string { return f.Head(head) }

// AppliedRef counts successful provider ref writes for the full ref name.
func (f *GitHub) AppliedRef(head string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refWrites[head]
}

// AppliedPull counts successful provider pull creation writes for a branch.
func (f *GitHub) AppliedPull(head string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pullWrites[head]
}

// RefReads counts provider ref readbacks for a branch.
func (f *GitHub) RefReads(head string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refReads["heads/"+head]
}

// PullReads counts provider pull list readbacks for a branch.
func (f *GitHub) PullReads(head string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pullReads[head]
}

// MergeReads counts authoritative pull-number reads for merge reconciliation.
func (f *GitHub) MergeReads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mergeReads
}

// PullNumber returns the pull created from the named fixture branch.
func (f *GitHub) PullNumber(head string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.pulls {
		if p.Head == head {
			return p.Number
		}
	}
	f.t.Fatalf("missing fake pull for %s", head)
	return 0
}

// SetApplyThenDrop drops the response after a successful ref or pull write.
func (f *GitHub) SetApplyThenDrop(ref, pull bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropRef, f.dropPull = ref, pull
}

// SetReadback controls provider read visibility without changing provider state.
func (f *GitHub) SetReadback(branch, pull ReadbackMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.branchMode, f.pullMode = branch, pull
}

// dropAnswer closes the connection after an applied write.
func dropAnswer(w http.ResponseWriter) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

// Owner is the fixture repository's owner.
func (f *GitHub) Owner() string { return f.owner }

// Repository is the fixture repository's name.
func (f *GitHub) Repository() string { return f.name }

// Token is a fake-only accepted installation credential.
func (f *GitHub) Token() string { return f.token }

// Head returns the current fixture branch head.
func (f *GitHub) Head(branch string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refs["heads/"+branch]
}

// MergeRequests counts attempted provider merge writes, including refusals.
func (f *GitHub) MergeRequests() int { f.mu.Lock(); defer f.mu.Unlock(); return f.mergeRequests }

// PushRequests counts attempted ref updates, including refused ones.
func (f *GitHub) PushRequests() int { f.mu.Lock(); defer f.mu.Unlock(); return f.pushRequests }

// AdvanceBranch models another writer advancing a branch after preparation.
func (f *GitHub) AdvanceBranch(branch string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	old, ok := f.refs["heads/"+branch]
	if !ok {
		f.t.Fatalf("missing fake branch %s", branch)
	}
	sha := f.putCommit(fakeCommit{Tree: f.commits[old].Tree, Parents: []string{old}, Message: "other writer"})
	f.refs["heads/"+branch] = sha
	return sha
}

// RewriteBranchFile models a concurrent force rewrite with the same parents
// and a different blob, keeping content and parent mismatch controls distinct.
func (f *GitHub) RewriteBranchFile(branch, path, content string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	old, ok := f.refs["heads/"+branch]
	if !ok {
		f.t.Fatalf("missing fake branch %s", branch)
	}
	commit := f.commits[old]
	entries := make(map[string]fakeEntry, len(f.trees[commit.Tree]))
	for name, entry := range f.trees[commit.Tree] {
		entries[name] = entry
	}
	entry, ok := entries[path]
	if !ok {
		f.t.Fatalf("missing fake branch file %s", path)
	}
	entry.Blob = blobSHA1(content)
	f.blobs[entry.Blob] = content
	entries[path] = entry
	commit.Tree = f.putTree(entries)
	commit.Message = "concurrent content rewrite"
	sha := f.putCommit(commit)
	f.refs["heads/"+branch] = sha
	return sha
}

// RewindBranch models a concurrent forced move to the current commit's parent.
func (f *GitHub) RewindBranch(branch string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	old, ok := f.refs["heads/"+branch]
	if !ok || len(f.commits[old].Parents) != 1 {
		f.t.Fatalf("missing rewindable fake branch %s", branch)
	}
	parent := f.commits[old].Parents[0]
	f.refs["heads/"+branch] = parent
	return parent
}

// SetMergeMode selects an acknowledged queue, pending request, or actual merge.
func (f *GitHub) SetMergeMode(mode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch mode {
	case "enqueued", "pending", "merged":
		f.mergeMode = mode
	default:
		f.t.Fatalf("unsupported fake merge mode %q", mode)
	}
}

// EditPull models an independent provider-side change under the fixture lock.
func (f *GitHub) EditPull(number int64, edit func(*PullRequest)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.pulls {
		if p.Number == number {
			edit(p)
			return
		}
	}
	f.t.Fatalf("missing fake pull %d", number)
}

// CompleteMerge makes the queued effect visible through the authoritative read.
func (f *GitHub) CompleteMerge(number int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.pulls {
		if p.Number == number {
			f.completeMerge(p)
			return
		}
	}
	f.t.Fatalf("missing fake pull %d", number)
}
func (f *GitHub) completeMerge(p *PullRequest) {
	if p.Merged {
		return
	}
	head := f.commits[p.HeadSHA]
	sha := f.putCommit(fakeCommit{Tree: head.Tree, Parents: []string{f.refs["heads/"+p.Base], p.HeadSHA}, Message: "merge pull"})
	p.Merged = true
	p.State = "closed"
	p.MergeCommitSHA = sha
	f.refs["heads/"+p.Base] = sha
}
func (f *GitHub) getPull(w http.ResponseWriter, raw string) {
	f.mergeReads++
	if f.pullMode == ReadbackInconclusive {
		f.fail(w, http.StatusServiceUnavailable, "Read-back unavailable")
		return
	}
	if f.pullMode == ReadbackAbsent {
		f.fail(w, http.StatusNotFound, "Not Found")
		return
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err == nil {
		for _, p := range f.pulls {
			if p.Number == n {
				answer := f.pullJSON(p)
				if f.pullMode == ReadbackMismatch {
					answer["head"].(map[string]any)["sha"] = strings.Repeat("f", 40)
				}
				f.write(w, http.StatusOK, answer)
				return
			}
		}
	}
	f.fail(w, http.StatusNotFound, "Not Found")
}
func (f *GitHub) mergePull(w http.ResponseWriter, r *http.Request, raw string, body map[string]any) {
	f.mergeRequests++
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		f.fail(w, http.StatusNotFound, "Not Found")
		return
	}
	for _, p := range f.pulls {
		if p.Number != n {
			continue
		}
		if r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || body["sha"] != p.HeadSHA || body["merge_action"] != "default" || body["bypass_rules"] != false || p.Draft || p.State != "open" {
			f.fail(w, http.StatusUnprocessableEntity, "merge precondition refused")
			return
		}
		method, _ := body["merge_method"].(string)
		if method != "merge" && method != "squash" && method != "rebase" {
			f.fail(w, http.StatusUnprocessableEntity, "bad merge method")
			return
		}
		status := http.StatusOK
		details := map[string]any{"message": "merge accepted"}
		switch f.mergeMode {
		case "pending":
			status = http.StatusAccepted
			details["uuid"] = "fake-merge-request"
			details["expected_head_sha"] = p.HeadSHA
			details["merge_method"] = method
			details["merge_action"] = "default"
			details["bypass_rules"] = false
		case "merged":
			f.completeMerge(p)
			details["sha"] = p.MergeCommitSHA
		}
		if f.dropPull {
			dropAnswer(w)
			return
		}
		f.write(w, status, map[string]any{"status": f.mergeMode, "details": details})
		return
	}
	f.fail(w, http.StatusNotFound, "Not Found")
}
func blobSHA1(content string) string {
	h := sha1.New() //nolint:gosec // git object addressing, independent provider fixture
	fmt.Fprintf(h, "blob %d\x00%s", len(content), content)
	return hex.EncodeToString(h.Sum(nil))
}
