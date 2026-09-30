package github

import (
	"crypto/sha1" //nolint:gosec // git object IDs
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fakeGitHub is an httptest GitHub that models the REST endpoints the adapter
// uses, with git's content addressing for blobs: a blob's ID is its real
// SHA-1, so the adapter's blob checks are exercised for real. Trees and
// commits get stable made-up IDs, and every commit is unique, as on GitHub,
// where the commit time is part of the ID.
type fakeGitHub struct {
	t      *testing.T
	owner  string
	name   string
	token  string
	server *httptest.Server

	mu      sync.Mutex
	blobs   map[string]string
	trees   map[string]map[string]fakeEntry
	commits map[string]fakeCommit
	refs    map[string]string // "heads/x" -> commit
	pulls   []*fakePull
	seq     int
}

type fakeEntry struct{ Mode, Blob string }

type fakeCommit struct {
	Tree    string
	Parents []string
	Message string
}

type fakePull struct {
	Number     int64
	Title      string
	Body       string
	Head, Base string
	HeadSHA    string
	Draft      bool
	State      string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{
		t: t, owner: "mindburn-qual", name: "sandbox", token: "ghs_fake_installation_token",
		blobs: map[string]string{}, trees: map[string]map[string]fakeEntry{},
		commits: map[string]fakeCommit{}, refs: map[string]string{},
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
	h := sha1.New() //nolint:gosec // made-up object IDs
	for _, p := range parts {
		io.WriteString(h, p)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (f *fakeGitHub) putTree(entries map[string]fakeEntry) string {
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

func (f *fakeGitHub) putCommit(c fakeCommit) string {
	f.seq++
	id := fakeID(append([]string{"commit", c.Tree, c.Message, fmt.Sprint(f.seq)}, c.Parents...)...)
	f.commits[id] = c
	return id
}

func (f *fakeGitHub) write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		f.t.Errorf("fake GitHub: encode: %v", err)
	}
}

func (f *fakeGitHub) fail(w http.ResponseWriter, status int, msg string) {
	f.write(w, status, map[string]string{"message": msg, "documentation_url": "https://docs.github.com/rest"})
}

func (f *fakeGitHub) repoJSON() map[string]any {
	return map[string]any{
		"id": 1, "node_id": "R_kgDOfake", "name": f.name, "full_name": f.owner + "/" + f.name,
		"private": true, "default_branch": "main", "visibility": "private",
		"owner":       map[string]any{"login": f.owner, "type": "Organization"},
		"permissions": map[string]bool{"admin": false, "push": true, "pull": true},
	}
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		f.fail(w, http.StatusUnauthorized, "Bad credentials")
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
	if r.Method == http.MethodPost {
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
		f.write(w, http.StatusOK, f.commitJSON(sha, c))
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
			f.write(w, http.StatusCreated, f.refJSON(name, sha))
		}
	case r.Method == http.MethodGet && strings.HasPrefix(rest, "/compare/"):
		f.compare(w, strings.TrimPrefix(rest, "/compare/"))
	case r.Method == http.MethodGet && rest == "/pulls":
		f.listPulls(w, r)
	case r.Method == http.MethodPost && rest == "/pulls":
		f.createPull(w, body)
	default:
		f.fail(w, http.StatusNotFound, "Not Found")
	}
}

func (f *fakeGitHub) refJSON(name, sha string) map[string]any {
	return map[string]any{
		"ref": "refs/" + name, "node_id": "REF_fake",
		"url":    f.server.URL + "/repos/" + f.owner + "/" + f.name + "/git/refs/" + name,
		"object": map[string]string{"sha": sha, "type": "commit"},
	}
}

func (f *fakeGitHub) commitJSON(sha string, c fakeCommit) map[string]any {
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

func (f *fakeGitHub) createTree(w http.ResponseWriter, body map[string]any) {
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

func (f *fakeGitHub) createCommit(w http.ResponseWriter, body map[string]any) {
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
func (f *fakeGitHub) compare(w http.ResponseWriter, spec string) {
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

func (f *fakeGitHub) pullJSON(p *fakePull) map[string]any {
	full := f.owner + "/" + f.name
	return map[string]any{
		"url":      f.server.URL + "/repos/" + full + "/pulls/" + fmt.Sprint(p.Number),
		"html_url": "https://github.com/" + full + "/pull/" + fmt.Sprint(p.Number),
		"id":       1000 + p.Number, "node_id": fmt.Sprintf("PR_kwDOfake%d", p.Number),
		"number": p.Number, "state": p.State, "title": p.Title, "body": p.Body, "draft": p.Draft,
		"locked": false, "user": map[string]string{"login": "helm-gateway[bot]"},
		"head": map[string]any{"label": f.owner + ":" + p.Head, "ref": p.Head, "sha": p.HeadSHA,
			"repo": map[string]any{"full_name": full}},
		"base": map[string]any{"label": f.owner + ":" + p.Base, "ref": p.Base,
			"sha": f.refs["heads/"+p.Base], "repo": map[string]any{"full_name": full}},
	}
}

func (f *fakeGitHub) listPulls(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" {
		state = "open"
	}
	out := []map[string]any{}
	for i := len(f.pulls) - 1; i >= 0; i-- { // newest first
		p := f.pulls[i]
		if (q.Get("head") == "" || q.Get("head") == f.owner+":"+p.Head) &&
			(q.Get("base") == "" || q.Get("base") == p.Base) && (state == "all" || state == p.State) {
			out = append(out, f.pullJSON(p))
		}
	}
	f.write(w, http.StatusOK, out)
}

func (f *fakeGitHub) createPull(w http.ResponseWriter, body map[string]any) {
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
	p := &fakePull{Number: int64(len(f.pulls) + 1), Title: title, Body: text, Head: head, Base: base, HeadSHA: headSHA, Draft: draft, State: "open"}
	f.pulls = append(f.pulls, p)
	f.write(w, http.StatusCreated, f.pullJSON(p))
}

// markReady turns a draft into a ready pull request, as a person would.
func (f *fakeGitHub) markReady(number int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.pulls {
		if p.Number == number {
			p.Draft = false
		}
	}
}
