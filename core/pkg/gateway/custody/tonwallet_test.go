package custody

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

func tonEffect(ref string) adapters.Effect {
	return adapters.Effect{EffectType: "ton.acton.script.testnet", Arguments: []byte(`{"wallet_ref":"` + ref + `"}`)}
}

func TestTONWalletsServeOnlyTheTenantsOwnWallet(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "w1")
	if err := os.WriteFile(secret, []byte("  s3cret words\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := NewTONWallets([]byte(`{"wallets":[{"tenant_id":"t1","wallet_ref":"wallet:a","secret_file":"` + secret + `"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if got, err := w.Token(ctx, "t1", tonEffect("wallet:a")); err != nil || got != "s3cret words" {
		t.Fatalf("own wallet: %q %v", got, err)
	}
	for name, c := range map[string]struct {
		tenant string
		e      adapters.Effect
	}{
		"another tenant":  {"t2", tonEffect("wallet:a")},
		"another ref":     {"t1", tonEffect("wallet:b")},
		"no ref":          {"t1", adapters.Effect{EffectType: "ton.acton.script.testnet", Arguments: []byte(`{}`)}},
		"not a ton token": {"t1", adapters.Effect{EffectType: "github.git.push", Arguments: []byte(`{"wallet_ref":"wallet:a"}`)}},
	} {
		if got, err := w.Token(ctx, c.tenant, c.e); err == nil || got != "" {
			t.Errorf("%s: got %q, want a refusal", name, got)
		}
	}
	if err := os.Remove(secret); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Token(ctx, "t1", tonEffect("wallet:a")); err == nil {
		t.Fatal("a missing secret file must fail closed")
	}
}

func TestTONWalletsFileIsClosed(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":         `{"wallets":[]}`,
		"unknown field": `{"wallets":[],"x":1}`,
		"bad ref":       `{"wallets":[{"tenant_id":"t","wallet_ref":"a","secret_file":"/x"}]}`,
		"duplicate":     `{"wallets":[{"tenant_id":"t","wallet_ref":"wallet:a","secret_file":"/x"},{"tenant_id":"t","wallet_ref":"wallet:a","secret_file":"/y"}]}`,
	} {
		if _, err := NewTONWallets([]byte(doc)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestRoutedSendsTONEffectsToTheWalletsOnly(t *testing.T) {
	gh := stubSource("gh-token")
	ton := stubSource("ton-secret")
	r := Routed{Default: gh, TON: ton}
	ctx := context.Background()
	if got, _ := r.Token(ctx, "t", adapters.Effect{EffectType: "github.git.push"}); got != "gh-token" {
		t.Fatalf("github effect: %q", got)
	}
	if got, _ := r.Token(ctx, "t", adapters.Effect{EffectType: "ton.acton.script.testnet"}); got != "ton-secret" {
		t.Fatalf("ton effect: %q", got)
	}
	if _, err := (Routed{TON: ton}).Token(ctx, "t", adapters.Effect{EffectType: "github.git.push"}); err == nil || !strings.Contains(err.Error(), "no credential") {
		t.Fatalf("a missing default custody must fail closed: %v", err)
	}
	if _, err := (Routed{Default: gh}).Token(ctx, "t", adapters.Effect{EffectType: "ton.acton.script.testnet"}); err == nil {
		t.Fatal("a TON effect must never fall back to the GitHub custody")
	}
}

type stubSource string

func (s stubSource) Token(context.Context, string, adapters.Effect) (string, error) {
	return string(s), nil
}
