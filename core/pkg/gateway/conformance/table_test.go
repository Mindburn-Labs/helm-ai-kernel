// Package conformance runs the gateway conformance table,
// protocols/conformance/gateway/v1, against the real helm-gateway: Postgres,
// a scripted adapter, the GitHub App custody and real token verification,
// over Connect. The table is what fakes of the gateway (the Control Plane's)
// pin, so a scenario the real gateway fails fails CI here (HELM-751).
//
// The package holds tests only.
//
// quantum_posture: computes SHA-256 digests of the table files to compare
// with the pinned ones; signs nothing here.
package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// The table as protocols/conformance/gateway/v1/scenario.schema.json defines
// it. Only what the runner reads is typed; the schema itself is enforced by
// the json-schemas gate (scripts/ci/check_json_schemas_test.py).

type pack struct {
	PackID         string     `json:"pack_id"`
	ScenarioSchema pinnedFile `json:"scenario_schema"`
	Scenarios      []struct {
		ID string `json:"id"`
		pinnedFile
	} `json:"scenarios"`
}

type pinnedFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

type scenario struct {
	Schema string `json:"schema"`
	ID     string `json:"id"`
	Title  string `json:"title"`
	Rule   struct {
		Statement string `json:"statement"`
		Cites     []struct {
			Doc     string `json:"doc"`
			Section string `json:"section"`
		} `json:"cites"`
	} `json:"rule"`
	Fixtures fixtures         `json:"fixtures"`
	Tokens   map[string]token `json:"tokens"`
	Steps    []step           `json:"steps"`
}

type fixtures struct {
	Tenants    []string `json:"tenants"`
	Principals []struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	} `json:"principals"`
	ConfiguredActor string `json:"configured_actor"`
	EffectTypes     []struct {
		EffectType string `json:"effect_type"`
		Risk       string `json:"risk"`
	} `json:"effect_types"`
	Mandates []struct {
		Holder           string            `json:"holder"`
		EffectTypes      []string          `json:"effect_types"`
		Targets          []string          `json:"targets"`
		Condition        string            `json:"condition"`
		ApprovalRequired []string          `json:"approval_required"`
		RiskClasses      map[string]string `json:"risk_classes"`
		Limits           []struct {
			Unit   string `json:"unit"`
			Window string `json:"window"`
			Value  int64  `json:"value"`
		} `json:"limits"`
		Activation struct {
			Requester string `json:"requester"`
			Approver  string `json:"approver"`
		} `json:"activation"`
	} `json:"mandates"`
	Adapter struct {
		EffectTypes []string          `json:"effect_types"`
		Dispatch    dispatchBehaviour `json:"dispatch"`
		Observe     observeBehaviour  `json:"observe"`
		Provider    struct {
			DefaultBranch    string `json:"default_branch"`
			DefaultBranchSHA string `json:"default_branch_sha"`
			BranchCommitSHA  string `json:"branch_commit_sha"`
		} `json:"provider"`
	} `json:"adapter"`
}

type dispatchBehaviour struct {
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code"`
}

type observeBehaviour struct {
	Status string `json:"status"`
}

type token struct {
	Scope                string          `json:"scope"`
	Sub                  string          `json:"sub"`
	ActSub               string          `json:"act_sub"`
	Tenant               string          `json:"tenant"`
	Workspace            string          `json:"workspace"`
	JTI                  string          `json:"jti"`
	AuthorizationDetails json.RawMessage `json:"authorization_details"`
}

type step struct {
	Note    string          `json:"note"`
	Label   string          `json:"label"`
	RPC     string          `json:"rpc"`
	Token   string          `json:"token"`
	Request json.RawMessage `json:"request"`
	Expect  *expect         `json:"expect"`
	Control *control        `json:"control"`
}

type control struct {
	Kind      string             `json:"kind"`
	Tenant    string             `json:"tenant"`
	ScopeKind string             `json:"scope_kind"`
	ScopeKey  string             `json:"scope_key"`
	IssuedBy  string             `json:"issued_by"`
	AttemptID string             `json:"attempt_id"`
	Dispatch  *dispatchBehaviour `json:"dispatch"`
	Observe   *observeBehaviour  `json:"observe"`
}

type expect struct {
	Attempt  *expectedAttempt `json:"attempt"`
	Existing *bool            `json:"existing"`
	Error    *struct {
		Code       string `json:"code"`
		ReasonCode string `json:"reason_code"`
	} `json:"error"`
	AdapterCalls *struct {
		Dispatch *int32 `json:"dispatch"`
		Observe  *int32 `json:"observe"`
	} `json:"adapter_calls"`
}

type expectedAttempt struct {
	State                *string `json:"state"`
	ReasonCode           *string `json:"reason_code"`
	Outcome              *string `json:"outcome"`
	OutcomeBasis         *string `json:"outcome_basis"`
	RiskClass            *string `json:"risk_class"`
	RequesterPrincipalID *string `json:"requester_principal_id"`
	RequesterActorID     *string `json:"requester_actor_id"`
	ApproverPrincipalID  *string `json:"approver_principal_id"`
	PendingApproval      *bool   `json:"pending_approval"`
	Permit               *string `json:"permit"`
	Exposure             *string `json:"exposure"`
	SameAttemptAs        *string `json:"same_attempt_as"`
}

// repoRoot is the repository checkout this file sits in.
func repoRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test file")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
}

func tableDir(t testing.TB) string {
	return filepath.Join(repoRoot(t), "protocols", "conformance", "gateway", "v1")
}

// loadScenario reads one scenario file. Unknown fields are an error, so a
// field the runner does not understand cannot pass unchecked.
func loadScenario(path string) (scenario, error) {
	var sc scenario
	data, err := os.ReadFile(path) // #nosec G304 -- a table file of this repository or a test's temp copy
	if err != nil {
		return sc, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sc); err != nil {
		return sc, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return sc, nil
}

var placeholder = regexp.MustCompile(`\{\{(attempt_id|approval_digest):([a-z0-9-]+)\}\}`)

// otherEscape is any JSON string escape but \", \\ and \n. The table uses
// only those three, so a fake's JSON.stringify of arguments_json and Go's
// json.Compact of its text give the same argument bytes.
var otherEscape = regexp.MustCompile(`\\[^"\\n]`)

// checkTable verifies what the schema cannot: the pack pins every file by
// SHA-256 and lists every scenario once; ids are unique and name their file;
// tokens and labels resolve; each citation names a file and section that
// exist. It returns the scenarios in pack order.
func checkTable(root, dir string) ([]scenario, error) {
	var p pack
	data, err := os.ReadFile(filepath.Join(dir, "conformance-pack.json")) // #nosec G304 -- the table's own manifest
	if err != nil {
		return nil, err
	}
	// The pack carries descriptive fields the runner does not read.
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("conformance-pack.json: %w", err)
	}
	var problems []string
	pinned := func(f pinnedFile) {
		body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.File))) // #nosec G304 -- a file the pack names
		if err != nil {
			problems = append(problems, err.Error())
			return
		}
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != f.SHA256 {
			problems = append(problems, fmt.Sprintf("%s: sha256 is %s, the pack pins %s", f.File, got, f.SHA256))
		}
	}
	pinned(p.ScenarioSchema)
	listed := map[string]bool{}
	ids := map[string]bool{}
	var out []scenario
	for _, entry := range p.Scenarios {
		pinned(entry.pinnedFile)
		listed[entry.File] = true
		if ids[entry.ID] {
			problems = append(problems, "scenario id "+entry.ID+" repeats")
		}
		ids[entry.ID] = true
		sc, err := loadScenario(filepath.Join(dir, filepath.FromSlash(entry.File)))
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if sc.ID != entry.ID || !strings.HasPrefix(filepath.Base(entry.File), sc.ID+"-") {
			problems = append(problems, fmt.Sprintf("%s: id %s does not match the pack entry %s", entry.File, sc.ID, entry.ID))
		}
		problems = append(problems, checkScenario(root, sc)...)
		out = append(out, sc)
	}
	files, err := filepath.Glob(filepath.Join(dir, "scenarios", "*.json"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if rel := "scenarios/" + filepath.Base(f); !listed[rel] {
			problems = append(problems, rel+" is not listed in conformance-pack.json")
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("the conformance table is inconsistent:\n  %s", strings.Join(problems, "\n  "))
	}
	return out, nil
}

func checkScenario(root string, sc scenario) []string {
	var problems []string
	bad := func(format string, args ...any) {
		problems = append(problems, sc.ID+": "+fmt.Sprintf(format, args...))
	}
	if sc.Schema != "helm.gateway.conformance.scenario.v1" {
		bad("schema is %q, want helm.gateway.conformance.scenario.v1", sc.Schema)
	}
	for _, c := range sc.Rule.Cites {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(c.Doc))) // #nosec G304 -- a repository document the scenario cites
		if err != nil {
			bad("cites %s, which does not exist", c.Doc)
			continue
		}
		if !citationHolds(string(body), c.Doc, c.Section) {
			bad("cites %s section %q, which it does not contain", c.Doc, c.Section)
		}
	}
	labels := map[string]bool{}
	resolves := func(where string, raw []byte) {
		for _, m := range placeholder.FindAllSubmatch(raw, -1) {
			if !labels[string(m[2])] {
				bad("%s names label %q before any step defines it", where, m[2])
			}
		}
	}
	for i, st := range sc.Steps {
		where := fmt.Sprintf("step %d", i+1)
		if st.Control != nil {
			resolves(where, []byte(st.Control.AttemptID))
			continue
		}
		if st.Expect == nil {
			bad("%s has no expect", where)
			continue
		}
		if st.Token != "" {
			tk, ok := sc.Tokens[st.Token]
			if !ok {
				bad("%s names token %q, which tokens does not define", where, st.Token)
			}
			resolves(where+" token "+st.Token, tk.AuthorizationDetails)
		}
		resolves(where, st.Request)
		if otherEscape.Match(st.Request) {
			bad("%s uses a string escape other than \\\", \\\\ and \\n", where)
		}
		if st.Expect.Attempt != nil {
			if st.RPC == "GetAttemptContent" {
				bad("%s expects an attempt from GetAttemptContent, which returns none", where)
			}
			if s := st.Expect.Attempt.SameAttemptAs; s != nil && !labels[*s] {
				bad("%s names label %q before any step defines it", where, *s)
			}
		}
		if st.Label != "" {
			if labels[st.Label] {
				bad("%s redefines label %q", where, st.Label)
			}
			labels[st.Label] = true
		}
	}
	return problems
}

// citationHolds: a Markdown section is a heading with exactly that text; in
// any other file the section is a string the file contains.
func citationHolds(body, doc, section string) bool {
	if !strings.HasSuffix(doc, ".md") {
		return strings.Contains(body, section)
	}
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "#") && strings.TrimSpace(strings.TrimLeft(line, "#")) == section {
			return true
		}
	}
	return false
}

// TestConformanceTableIsConsistent needs no database: every scenario loads
// with no unknown field, the pack's pins hold, and every reference resolves.
func TestConformanceTableIsConsistent(t *testing.T) {
	root, dir := repoRoot(t), tableDir(t)
	scenarios, err := checkTable(root, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(scenarios) < 18 {
		t.Fatalf("the table has %d scenarios; the HELM-751 minimum set is 18", len(scenarios))
	}

	// Known bad: a byte changed in a pinned scenario, an unlisted file and a
	// citation of a section that does not exist are each reported.
	planted := t.TempDir()
	must(t, os.CopyFS(planted, os.DirFS(dir)))
	first := filepath.Join(planted, filepath.FromSlash("scenarios/GW-001-walking-skeleton.json"))
	body, err := os.ReadFile(first) // #nosec G304 -- the test's own temp copy
	must(t, err)
	body = bytes.Replace(body, []byte("The HELM-789 walking skeleton"), []byte("The HELM-789 walking skeleton."), 1)
	must(t, os.WriteFile(first, body, 0o600))
	must(t, os.WriteFile(filepath.Join(planted, "scenarios", "GW-999-unlisted.json"), []byte("{}"), 0o600))
	_, err = checkTable(root, planted)
	for _, want := range []string{"GW-001-walking-skeleton.json: sha256 is", "GW-999-unlisted.json is not listed"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("a planted inconsistency was not reported (%q): %v", want, err)
		}
	}
	sc := scenarios[0]
	sc.Rule.Cites = append(sc.Rule.Cites, struct {
		Doc     string `json:"doc"`
		Section string `json:"section"`
	}{Doc: "docs/architecture/gateway-effect-api.md", Section: "A section nobody wrote"})
	if problems := checkScenario(root, sc); len(problems) != 1 || !strings.Contains(problems[0], "A section nobody wrote") {
		t.Fatalf("a citation of a missing section was not reported: %v", problems)
	}
	sc = scenarios[0]
	sc.Steps = append([]step(nil), sc.Steps...)
	sc.Steps[0].Request = json.RawMessage(`{"idempotency_key":"a\tb"}`)
	if problems := checkScenario(root, sc); len(problems) != 1 || !strings.Contains(problems[0], "string escape") {
		t.Fatalf("a tab escape was not reported: %v", problems)
	}
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
