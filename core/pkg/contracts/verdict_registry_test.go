package contracts

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"
)

type registryFile struct {
	Version string            `json:"version"`
	Codes   []reasonCodeEntry `json:"codes"`
}

type reasonCodeEntry struct {
	Code      string   `json:"code"`
	AppliesTo []string `json:"applies_to"`
}

func TestCanonicalVerdicts_AreStable(t *testing.T) {
	got := CanonicalVerdicts()
	want := []Verdict{VerdictAllow, VerdictDeny, VerdictEscalate}
	if !slices.Equal(got, want) {
		t.Fatalf("canonical verdicts mismatch: got %v want %v", got, want)
	}
}

func TestReasonCodeRegistry_MatchesContracts(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller")
	}
	registryPath := filepath.Join(
		filepath.Dir(thisFile),
		"..", "..", "..",
		"protocols", "json-schemas", "reason-codes", "reason-codes-v1.json",
	)

	var registry registryFile
	loadJSONFile(t, registryPath, &registry)
	if registry.Version != "1.0.0" {
		t.Fatalf("unexpected registry version %q", registry.Version)
	}

	seen := map[string]struct{}{}
	for _, entry := range registry.Codes {
		if entry.Code == "" {
			t.Fatal("registry contains empty reason code")
		}
		if _, exists := seen[entry.Code]; exists {
			t.Fatalf("duplicate reason code %q in registry", entry.Code)
		}
		seen[entry.Code] = struct{}{}
		for _, verdict := range entry.AppliesTo {
			if verdict == string(VerdictAllow) {
				t.Fatalf("reason code %q incorrectly applies to ALLOW", entry.Code)
			}
			if !IsCanonicalVerdict(verdict) {
				t.Fatalf("reason code %q has non-canonical verdict %q", entry.Code, verdict)
			}
		}
	}

	var got []string
	for _, reason := range CoreReasonCodes() {
		got = append(got, string(reason))
	}
	slices.Sort(got)

	var want []string
	for _, entry := range registry.Codes {
		want = append(want, entry.Code)
	}
	slices.Sort(want)

	if !slices.Equal(got, want) {
		t.Fatalf("core reason-code registry mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func loadJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

// TestReasonCodeDeclarations_MatchRegistry parses verdict.go and requires its
// ReasonCode constants to be exactly the generated registry: no constant
// outside the registry, no registry code without a kernel name, no two names
// for one code.
func TestReasonCodeDeclarations_MatchRegistry(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "verdict.go", nil, 0)
	if err != nil {
		t.Fatalf("parse verdict.go: %v", err)
	}
	declared := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value := spec.(*ast.ValueSpec)
			if typ, ok := value.Type.(*ast.Ident); !ok || typ.Name != "ReasonCode" {
				continue
			}
			for i, name := range value.Names {
				code, err := strconv.Unquote(value.Values[i].(*ast.BasicLit).Value)
				if err != nil {
					t.Fatalf("%s: %v", name.Name, err)
				}
				if previous, dup := declared[code]; dup {
					t.Errorf("%s and %s both name %q", previous, name.Name, code)
				}
				declared[code] = name.Name
			}
		}
	}

	registered := map[string]bool{}
	for _, code := range CoreReasonCodes() {
		registered[string(code)] = true
		if _, ok := declared[string(code)]; !ok {
			t.Errorf("registry code %q has no ReasonCode constant in verdict.go", code)
		}
	}
	for code, name := range declared {
		if !registered[code] {
			t.Errorf("%s = %q is not in reason-codes-v1.json", name, code)
		}
	}
	if len(declared) == 0 {
		t.Fatal("no ReasonCode constants parsed from verdict.go")
	}
}
