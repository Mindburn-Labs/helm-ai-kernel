package policybundles

import (
	"context"
	"strings"
	"testing"
)

func TestSupportedLanguages_StableOrder(t *testing.T) {
	got := SupportedLanguages()
	want := []string{"cel", "rego", "cedar"}
	if len(got) != len(want) {
		t.Fatalf("len(got)=%d want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestLanguageFromExtension(t *testing.T) {
	cases := map[string]string{
		"a.cel":          LanguageCEL,
		"a.rego":         LanguageRego,
		"a.cedar":        LanguageCedar,
		"a.json":         "",
		"":               "",
		"path/to/x.REGO": LanguageRego, // case-insensitive
	}
	for in, want := range cases {
		if got := LanguageFromExtension(in); got != want {
			t.Errorf("LanguageFromExtension(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsSupportedLanguage(t *testing.T) {
	for _, l := range []string{"cel", "rego", "cedar"} {
		if !IsSupportedLanguage(l) {
			t.Errorf("expected %q supported", l)
		}
	}
	for _, l := range []string{"", "yaml", "python"} {
		if IsSupportedLanguage(l) {
			t.Errorf("expected %q NOT supported", l)
		}
	}
}

func TestDetectLanguage(t *testing.T) {
	got, err := DetectLanguage("", "policy.rego")
	if err != nil {
		t.Fatalf("from extension: %v", err)
	}
	if got != LanguageRego {
		t.Errorf("got=%q want=%q", got, LanguageRego)
	}

	got, err = DetectLanguage("cedar", "policy.rego")
	if err != nil {
		t.Fatalf("explicit override: %v", err)
	}
	if got != LanguageCedar {
		t.Errorf("explicit override returned %q want cedar", got)
	}

	if _, err := DetectLanguage("", "policy.txt"); err == nil {
		t.Error("expected unknown extension to fail")
	}

	if _, err := DetectLanguage("python", "policy.rego"); err == nil {
		t.Error("expected unsupported explicit language to fail")
	}
}

func TestCompile_Rego(t *testing.T) {
	src := `package helm.policy

import rego.v1

default decision := {"verdict": "DENY", "reason": "default deny"}

decision := {"verdict": "ALLOW"} if {
	input.action == "view"
}
`
	got, err := Compile(context.Background(), LanguageRego, src, CompileOptions{
		BundleID: "registry-rego-1",
		Name:     "Registry Rego Test",
	})
	if err != nil {
		t.Fatalf("Compile rego: %v", err)
	}
	if got.Language != LanguageRego {
		t.Errorf("Language=%q want %q", got.Language, LanguageRego)
	}
	if got.Rego == nil {
		t.Fatal("Rego field nil")
	}
	if got.Cedar != nil {
		t.Error("Cedar field should be nil for rego compile")
	}
	if !strings.HasPrefix(got.Hash, "sha256:") {
		t.Errorf("Hash=%q want sha256: prefix", got.Hash)
	}
}

func TestCompile_Cedar(t *testing.T) {
	src := `permit(principal, action, resource);`
	got, err := Compile(context.Background(), LanguageCedar, src, CompileOptions{
		BundleID: "registry-cedar-1",
		Name:     "Registry Cedar Test",
	})
	if err != nil {
		t.Fatalf("Compile cedar: %v", err)
	}
	if got.Language != LanguageCedar {
		t.Errorf("Language=%q want %q", got.Language, LanguageCedar)
	}
	if got.Cedar == nil {
		t.Fatal("Cedar field nil")
	}
	if got.Rego != nil {
		t.Error("Rego field should be nil for cedar compile")
	}
}

func TestCompile_CELReturnsSentinel(t *testing.T) {
	_, err := Compile(context.Background(), LanguageCEL, "request.action == 'view'", CompileOptions{})
	if err == nil {
		t.Fatal("expected sentinel error for CEL through registry")
	}
	if !strings.Contains(err.Error(), "celcheck") {
		t.Errorf("error message should mention celcheck path; got %q", err.Error())
	}
}

func TestCompile_UnsupportedLanguage(t *testing.T) {
	_, err := Compile(context.Background(), "python", "x", CompileOptions{})
	if err == nil {
		t.Fatal("expected unsupported language error")
	}
}
