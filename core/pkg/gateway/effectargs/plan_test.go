package effectargs

// quantum_posture: computes SHA-256 plan digests to compare with a published
// vector; signs nothing.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	planOrg = "org:0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d"
	// The digest of provision.v1.valid.json, which the contract test in
	// sdk/go/gen/helm/gateway/v1 and an independent Python program also compute.
	planVector = "70d6c47ca51186780504038bdadb939319455ee16c14f59d4829fd1a8bdee5af"
	// The digest of provision.v1.valid-escapes.json, whose condition carries "&&",
	// "<" and ">" and whose target carries non-ASCII text, a character beyond the
	// BMP and U+2028: what an encoder that is not RFC 8785 writes differently.
	escapesVector = "81bbed39150fdb7cc7988f955bcdb6be75b150b07b8ca8cd0fe425ffb386b4ef"
)

func planExamples(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "protocols", "json-schemas", "effects", "authority", "examples")
}

func readExample(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(planExamples(t), name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A plan is edited as a JSON document: fn changes the decoded object, which is
// encoded again with the numbers as they were written.
func editPlan(t *testing.T, raw []byte, fn func(map[string]any)) []byte {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	fn(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPlanDigestMatchesThePublishedVector(t *testing.T) {
	raw := readExample(t, "provision.v1.valid.json")
	plan, err := ParsePlan(AuthorityProvision, raw)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Digest != planVector {
		t.Fatalf("plan digest = %s, want %s", plan.Digest, planVector)
	}
	if plan.OrgRef != planOrg || plan.Stage != "approval-required" || len(plan.Mandates) < 3 {
		t.Fatalf("parsed plan = %+v", plan)
	}
	escapes, err := ParsePlan(AuthorityProvision, readExample(t, "provision.v1.valid-escapes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if escapes.Digest != escapesVector {
		t.Fatalf("escapes plan digest = %s, want %s", escapes.Digest, escapesVector)
	}
	// Planted: encoding/json's compact form of the same plan, which escapes "&",
	// "<" and ">", is a different byte string; the digest is not over it.
	naive, err := json.Marshal(decodeForTest(t, readExample(t, "provision.v1.valid-escapes.json")))
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(naive); hex.EncodeToString(sum[:]) == escapesVector {
		t.Fatal("the escapes plan does not tell RFC 8785 from encoding/json")
	}
}

func decodeForTest(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "base_plan_digest")
	return doc
}

// The digest is over the RFC 8785 form of the arguments without
// base_plan_digest: the member order, the whitespace and the base do not move
// it, and any other change does.
func TestPlanDigestIsTheCanonicalFormWithoutTheBase(t *testing.T) {
	raw := readExample(t, "provision.v1.valid.json")
	base := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	rebased := editPlan(t, raw, func(doc map[string]any) { doc["base_plan_digest"] = base })
	plan, err := ParsePlan(AuthorityProvision, rebased)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Digest != planVector || plan.BaseDigest != base {
		t.Fatalf("digest %s base %s: the base must not move the digest", plan.Digest, plan.BaseDigest)
	}
	// encoding/json writes the members sorted and compact: a different byte
	// form of the same document.
	if string(rebased) == string(raw) {
		t.Fatal("the edit did not change the bytes")
	}
	changed := editPlan(t, raw, func(doc map[string]any) { doc["version_ref"] = "another" })
	other, err := ParsePlan(AuthorityProvision, changed)
	if err != nil {
		t.Fatal(err)
	}
	if other.Digest == planVector {
		t.Fatal("a changed plan kept its digest")
	}
}

// Every valid fixture of protocols/json-schemas/effects/authority/examples is
// accepted, and every invalid one is refused unless it is refused by the plan's
// compilation against the store's rules rather than by its syntax (the
// authority adapter's test runs all of them through Check).
func TestParsePlanAcceptsTheValidFixturesAndRefusesTheInvalidOnes(t *testing.T) {
	entries, err := os.ReadDir(planExamples(t))
	if err != nil {
		t.Fatal(err)
	}
	compileLevel := map[string]bool{"provision.v1.invalid-child-wider-than-parent.json": true}
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		effectType := AuthorityProvision
		if strings.HasPrefix(name, "narrow.v1.") {
			effectType = AuthorityNarrow
		}
		_, err := ParsePlan(effectType, readExample(t, name))
		valid := strings.Contains(name, ".valid")
		switch {
		case valid && err != nil:
			t.Errorf("%s: %v", name, err)
		case !valid && compileLevel[name]:
		case !valid && err == nil:
			t.Errorf("%s: accepted an invalid fixture", name)
		case !valid && !errors.Is(err, ErrInvalid):
			t.Errorf("%s: %v does not wrap ErrInvalid", name, err)
		}
		checked++
	}
	if checked < 25 {
		t.Fatalf("checked %d fixtures", checked)
	}
}

// Rules the schema cannot state.
func TestParsePlanRefusesWhatTheSchemaCannotState(t *testing.T) {
	raw := readExample(t, "provision.v1.valid.json")
	mandate := func(doc map[string]any, i int) map[string]any { return doc["mandates"].([]any)[i].(map[string]any) }
	terms := func(doc map[string]any, i int) map[string]any { return mandate(doc, i)["terms"].(map[string]any) }
	cases := map[string]func(map[string]any){
		"until before from":    func(d map[string]any) { d["valid_until"] = "2026-09-01T00:00:00Z" },
		"two roots":            func(d map[string]any) { mandate(d, 1)["parent"] = nil },
		"root is not the org":  func(d map[string]any) { mandate(d, 0)["node"] = "org:other" },
		"unknown parent":       func(d map[string]any) { mandate(d, 1)["parent"] = "team:nobody" },
		"self parent":          func(d map[string]any) { mandate(d, 1)["parent"] = mandate(d, 1)["node"] },
		"duplicate node":       func(d map[string]any) { mandate(d, 2)["node"] = mandate(d, 1)["node"] },
		"unlisted effect type": func(d map[string]any) { terms(d, 1)["effect_types"] = []any{"ops.note"} },
		"own effect granted":   func(d map[string]any) { terms(d, 1)["effect_types"] = []any{AuthorityProvision} },
		"disabled holder": func(d map[string]any) {
			d["disable_principals"] = []any{mandate(d, 2)["holder"]}
		},
		"listed and disabled": func(d map[string]any) {
			d["disable_principals"] = []any{d["principals"].([]any)[0].(map[string]any)["id"]}
		},
		"limit on a stranger": func(d map[string]any) {
			d["limits"] = []any{map[string]any{"node": "team:nobody", "unit": "count", "measure": "count", "window": "day", "value": json.Number("1")}}
		},
		"duplicate limit": func(d map[string]any) {
			l := map[string]any{"node": mandate(d, 1)["node"], "unit": "count", "measure": "count", "window": "day", "value": json.Number("1")}
			d["limits"] = []any{l, l}
		},
		"span on a none window": func(d map[string]any) {
			d["limits"] = []any{map[string]any{"node": mandate(d, 1)["node"], "unit": "count", "measure": "count", "window": "none", "value": json.Number("1"), "span": json.Number("2")}}
		},
		"human without a subject": func(d map[string]any) {
			d["principals"] = append(d["principals"].([]any), map[string]any{"id": "usr_other", "kind": "human"})
		},
		"fractional amount": func(d map[string]any) { terms(d, 1)["per_call_limit"] = json.Number("1.0") },
		"exponent amount":   func(d map[string]any) { terms(d, 1)["per_call_limit"] = json.Number("1e3") },
		"approval outside the terms": func(d map[string]any) {
			terms(d, 1)["approval_required"] = []any{"ops.note"}
		},
	}
	for name, edit := range cases {
		if _, err := ParsePlan(AuthorityProvision, editPlan(t, raw, edit)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if _, err := ParsePlan(AuthorityNarrow, raw); !errors.Is(err, ErrInvalid) {
		t.Errorf("a provision plan is not a narrow plan: err = %v", err)
	}
}

func TestParsePlanRefusesFoldedKeysDuplicatesAndOversize(t *testing.T) {
	raw := readExample(t, "provision.v1.valid.json")
	cases := map[string][]byte{
		"folded key":     []byte(strings.Replace(string(raw), `"stage"`, `"Stage"`, 1)),
		"long-s schema":  []byte(strings.Replace(string(raw), `"schema"`, "\"ſchema\"", 1)),
		"duplicate key":  []byte(strings.Replace(string(raw), `"stage": "approval-required",`, `"stage": "approval-required", "stage": "draft",`, 1)),
		"not an object":  []byte(`[]`),
		"not UTF-8":      append([]byte(`{"schema":"`), 0xff, '"', '}'),
		"trailing bytes": append(append([]byte{}, raw...), []byte(` {}`)...),
		"over the cap":   []byte(`{"schema":"` + AuthorityProvision + `","pad":"` + strings.Repeat("x", MaxPlanBytes) + `"}`),
	}
	for name, doc := range cases {
		if _, err := ParsePlan(AuthorityProvision, doc); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

// Validate hands a plan to ParsePlan, with the plan's own size cap, and holds
// the target to the organization: a plan for one organization cannot ride on
// another's target.
func TestValidateRoutesThePlanEffects(t *testing.T) {
	raw := readExample(t, "provision.v1.valid.json")
	args, err := Validate(AuthorityProvision, planOrg, raw)
	if err != nil {
		t.Fatal(err)
	}
	if args["org_ref"] != planOrg || args["schema"] != AuthorityProvision {
		t.Fatalf("parsed = %v", args)
	}
	if len(raw) <= MaxBytes {
		// a small plan passes under either cap; the routing is what matters
		if _, err := Validate(AuthorityProvision, "org:other", raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("a target that is not the org_ref: err = %v", err)
		}
	}
	// A plan larger than an ordinary effect's 64 KiB, under its own cap.
	big := editPlan(t, raw, func(doc map[string]any) {
		types := doc["effect_types"].([]any)
		doc["version_ref"] = "big"
		for i := 0; i < 40; i++ {
			name := "bulk.effect" + strings.Repeat("x", 100) + string(rune('a'+i%26)) + string(rune('a'+i/26))
			types = append(types, map[string]any{"effect_type": name, "risk_class": "low"})
		}
		doc["effect_types"] = types
	})
	if _, err := Validate(AuthorityProvision, planOrg, big); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(GitHubRepositoryGet, planOrg, []byte(`{"schema":"`+strings.Repeat("x", MaxBytes)+`"}`)); !errors.Is(err, ErrInvalid) {
		t.Errorf("an ordinary effect keeps its 64 KiB cap: err = %v", err)
	}
	if IsAuthorityPlan(AuthorityLift) || !IsAuthorityPlan(AuthorityNarrow) {
		t.Error("IsAuthorityPlan names exactly the two plan effects")
	}
}
