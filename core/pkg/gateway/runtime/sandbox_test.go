package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

// configWithSigner is an admission config holding the gateway's receipt signer.
func configWithSigner(t *testing.T, credentials admission.Credentials) admission.Config {
	t.Helper()
	signer, err := crypto.NewEd25519SignerFromSeed(testReceiptSeed, testReceiptKeyID)
	if err != nil {
		t.Fatal(err)
	}
	return admission.Config{ReceiptSigner: signer, Credentials: credentials}
}

func getenvOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

type githubStub struct{}

func (githubStub) Token(context.Context, string, adapters.Effect) (string, error) {
	return "github-installation-token", nil
}

// Sandbox providers are off unless an operator configures them: with no
// configuration the gateway has no sandbox effect type and its credentials are
// untouched.
func TestSandboxEffectsAreOffUnlessConfigured(t *testing.T) {
	c := configWithSigner(t, githubStub{})
	if err := sandboxFromEnv(getenvOf(nil), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Adapters) != 0 {
		t.Fatalf("an unconfigured gateway gained adapters: %v", c.Adapters)
	}
	if _, ok := c.Credentials.(githubStub); !ok {
		t.Fatalf("an unconfigured gateway changed its credentials: %T", c.Credentials)
	}
}

func TestSandboxEffectsAreWiredFromTheConfigurationFile(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "e2b-key")
	if err := os.WriteFile(key, []byte("canary-e2b-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "sandbox.json")
	body := `{"providers":[{"provider":"e2b","key_file":"` + key + `","api_url":"https://api.e2b.dev","template_id":"base"},{"provider":"docker"}]}`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c := configWithSigner(t, githubStub{})
	if err := sandboxFromEnv(getenvOf(map[string]string{envSandboxConfigFile: cfg}), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Adapters) != 1 {
		t.Fatalf("adapters = %v", c.Adapters)
	}
	var effects []string
	for _, d := range c.Adapters[0].Declarations() {
		effects = append(effects, d.EffectType)
		if len(d.ArgumentSchema) == 0 || len(d.ResultSchema) == 0 || !d.Grantable {
			t.Errorf("%s is declared without its schemas", d.EffectType)
		}
	}
	if strings.Join(effects, ",") != "sandbox.create,sandbox.exec,sandbox.terminate" {
		t.Fatalf("effects = %v", effects)
	}
	// The provider key reaches only sandbox effects of its provider; GitHub
	// effects keep the GitHub credentials, and Docker has no key.
	ctx := context.Background()
	got, err := c.Credentials.Token(ctx, "t", adapters.Effect{EffectType: "sandbox.create", Target: "sandbox/e2b"})
	if err != nil || got != "canary-e2b-key" {
		t.Fatalf("e2b key = %q, %v", got, err)
	}
	if _, err := c.Credentials.Token(ctx, "t", adapters.Effect{EffectType: "sandbox.create", Target: "sandbox/docker"}); err == nil {
		t.Fatal("docker was given a key")
	}
	got, err = c.Credentials.Token(ctx, "t", adapters.Effect{EffectType: "github.repository.get", Target: "github.com/o/r"})
	if err != nil || got != "github-installation-token" {
		t.Fatalf("github token = %q, %v", got, err)
	}
	// The GitHub activity trail still sees the GitHub credentials alone, and
	// sees none when there is no GitHub App.
	if _, ok := withoutSandboxRoute(c.Credentials).(githubStub); !ok {
		t.Fatalf("the activity trail's credentials = %T", withoutSandboxRoute(c.Credentials))
	}
	bare := configWithSigner(t, nil)
	if err := sandboxFromEnv(getenvOf(map[string]string{envSandboxConfigFile: cfg}), &bare); err != nil {
		t.Fatal(err)
	}
	if withoutSandboxRoute(bare.Credentials) != nil {
		t.Fatal("sandbox credentials were taken for GitHub App credentials")
	}
}

func TestSandboxConfigurationErrorsStopTheGateway(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, env := range map[string]string{
		"missing file":            filepath.Join(dir, "absent.json"),
		"malformed":               write("bad.json", `{`),
		"unknown provider":        write("unknown.json", `{"providers":[{"provider":"modal","key_file":"/k"}]}`),
		"a key file that is gone": write("nokey.json", `{"providers":[{"provider":"e2b","key_file":"`+filepath.Join(dir, "gone")+`"}]}`),
		"oversized":               write("big.json", `{"providers":[{"provider":"docker","docker_bin":"`+strings.Repeat("a", 70000)+`"}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			c := configWithSigner(t, nil)
			if err := sandboxFromEnv(getenvOf(map[string]string{envSandboxConfigFile: env}), &c); err == nil {
				t.Fatal("the gateway started with an unusable sandbox configuration")
			}
			if len(c.Adapters) != 0 {
				t.Fatal("a failed configuration left an adapter behind")
			}
		})
	}
}
