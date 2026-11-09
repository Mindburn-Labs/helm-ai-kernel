package effectargs

import "testing"

func TestSandboxTargetsComeOnlyFromTheTarget(t *testing.T) {
	type want struct{ provider, id string }
	for _, c := range []struct {
		effectType, target string
		want               *want
	}{
		{SandboxCreate, "sandbox/e2b", &want{"e2b", ""}},
		{SandboxCreate, "sandbox/claude-managed-agents", &want{"claude-managed-agents", ""}},
		{SandboxExec, "sandbox/docker/helm-sbx-0123456789abcdef", &want{"docker", "helm-sbx-0123456789abcdef"}},
		{SandboxTerminate, "sandbox/daytona/i3x9k2.m", &want{"daytona", "i3x9k2.m"}},
		{SandboxCreate, "sandbox/e2b/sbx-1", nil},
		{SandboxExec, "sandbox/e2b", nil},
		{SandboxExec, "sandbox/e2b/", nil},
		{SandboxExec, "sandbox/e2b/../x", nil},
		{SandboxExec, "sandbox/e2b/a/b", nil},
		{SandboxExec, "sandbox/e2b/-rf", nil},
		{SandboxExec, "sandbox/e2b/a b", nil},
		{SandboxCreate, "sandbox/modal", nil},
		{SandboxCreate, "sandbox/E2B", nil},
		{SandboxCreate, "https://api.e2b.dev", nil},
		{SandboxCreate, "sandbox", nil},
		{SandboxCreate, "", nil},
		{"github.git.push", "sandbox/e2b", nil},
	} {
		provider, id, err := SandboxTarget(c.effectType, c.target)
		switch {
		case c.want == nil && err == nil:
			t.Errorf("%s %q was accepted", c.effectType, c.target)
		case c.want != nil && (err != nil || provider != c.want.provider || id != c.want.id):
			t.Errorf("%s %q = %q %q %v, want %+v", c.effectType, c.target, provider, id, err, *c.want)
		}
	}
}

func TestValidateChecksASandboxEffectsTargetBeforeAdmission(t *testing.T) {
	if _, err := Validate(SandboxExec, "sandbox/e2b/sbx-1", []byte(`{"schema":"helm.sandbox.exec.v1"}`)); err != nil {
		t.Fatalf("a well-formed target: %v", err)
	}
	for _, target := range []string{"sandbox/e2b", "sandbox/nope/sbx-1", "github.com/x/y"} {
		if _, err := Validate(SandboxExec, target, []byte(`{"schema":"helm.sandbox.exec.v1"}`)); err == nil {
			t.Errorf("target %q was accepted", target)
		}
	}
	for _, effectType := range []string{SandboxCreate, SandboxExec, SandboxTerminate} {
		if !IsSandboxEffect(effectType) {
			t.Errorf("%s is a sandbox effect", effectType)
		}
	}
	if IsSandboxEffect("github.git.push") || IsSandboxEffect("sandbox.other") {
		t.Error("only the three sandbox effects are sandbox effects")
	}
}
