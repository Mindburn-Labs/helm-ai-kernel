package custody

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

func TestSandboxKeysServeTheTargetProvidersKeyOnly(t *testing.T) {
	dir := t.TempDir()
	keys, err := NewSandboxKeys(map[string]string{
		"e2b":     writeKey(t, dir, "e2b", "canary-e2b-key\n"),
		"daytona": writeKey(t, dir, "daytona", "canary-daytona-key\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{"sandbox/e2b": "canary-e2b-key", "sandbox/daytona/sbx-1": "canary-daytona-key"} {
		effectType := "sandbox.create"
		if strings.Count(target, "/") == 2 {
			effectType = "sandbox.exec"
		}
		got, err := keys.Token(context.Background(), "tenant", adapters.Effect{EffectType: effectType, Target: target})
		if err != nil || got != want {
			t.Fatalf("Token(%s) = %q, %v; want %q", target, got, err, want)
		}
	}
	// A provider with no key file, a malformed target and a non-sandbox
	// effect have none, and the error never carries a key.
	for name, effect := range map[string]adapters.Effect{
		"unconfigured provider": {EffectType: "sandbox.create", Target: "sandbox/opensandbox"},
		"malformed target":      {EffectType: "sandbox.create", Target: "sandbox/e2b/../daytona"},
		"another effect":        {EffectType: "github.repository.get", Target: "github.com/o/r"},
	} {
		_, err := keys.Token(context.Background(), "tenant", effect)
		if err == nil || strings.Contains(err.Error(), "canary") {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if _, err := (*SandboxKeys)(nil).Token(context.Background(), "t", adapters.Effect{EffectType: "sandbox.create", Target: "sandbox/e2b"}); !errors.Is(err, ErrNoProviderKey) {
		t.Fatalf("a nil custody has no key: %v", err)
	}
}

func TestSandboxKeysForKeylessProvidersOnlyAndABadFile(t *testing.T) {
	keys, err := NewSandboxKeys(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Token(context.Background(), "t", adapters.Effect{EffectType: "sandbox.create", Target: "sandbox/e2b"}); !errors.Is(err, ErrNoProviderKey) {
		t.Fatalf("no key files, no keys: %v", err)
	}
	if _, err := NewSandboxKeys(map[string]string{"e2b": "/nonexistent/key"}); err == nil {
		t.Fatal("a missing key file was accepted")
	}
}

type staticCreds string

func (s staticCreds) Token(context.Context, string, adapters.Effect) (string, error) {
	return string(s), nil
}

func TestRouteSendsSandboxEffectsToTheSandboxCustodyAndTheRestAway(t *testing.T) {
	r := Route{Sandbox: staticCreds("sandbox-key"), Rest: staticCreds("github-token")}
	ctx := context.Background()
	for _, c := range []struct {
		effect adapters.Effect
		want   string
	}{
		{adapters.Effect{EffectType: "sandbox.exec", Target: "sandbox/e2b/x"}, "sandbox-key"},
		{adapters.Effect{EffectType: "github.repository.get", Target: "github.com/o/r"}, "github-token"},
		{adapters.Effect{EffectType: "github.pull_request.merge", Target: "github.com/o/r"}, "github-token"},
	} {
		if got, err := r.Token(ctx, "t", c.effect); err != nil || got != c.want {
			t.Fatalf("%s = %q, %v; want %q", c.effect.EffectType, got, err, c.want)
		}
	}
	// A route missing a half has no credentials for it, and never falls
	// through to the other.
	if _, err := (Route{Rest: staticCreds("github-token")}).Token(ctx, "t", adapters.Effect{EffectType: "sandbox.create", Target: "sandbox/e2b"}); err == nil {
		t.Fatal("a sandbox effect got the GitHub credentials")
	}
	if _, err := (Route{Sandbox: staticCreds("sandbox-key")}).Token(ctx, "t", adapters.Effect{EffectType: "github.repository.get"}); err == nil {
		t.Fatal("a GitHub effect got the sandbox credentials")
	}
}
