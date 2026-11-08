package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTONActonIsOptionalAndAllOrNothing(t *testing.T) {
	if a, w, err := tonActonFromEnv(env(nil)); a != nil || w != nil || err != nil {
		t.Fatalf("unconfigured: %v %v %v", a, w, err)
	}
	dir := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "acton")
	for name, m := range map[string]map[string]string{
		"bin without workspace":   {envTONActonBin: bin},
		"workspace without bin":   {envTONActonWorkspace: dir},
		"testnet settings alone":  {envTONRPCURL: "https://x.example"},
		"rpc without wallets":     {envTONActonBin: bin, envTONActonWorkspace: dir, envTONRPCURL: "https://x.example"},
		"relative binary":         {envTONActonBin: "acton", envTONActonWorkspace: dir},
		"plain http remote rpc":   {envTONActonBin: bin, envTONActonWorkspace: dir, envTONRPCURL: "http://x.example"},
		"wallets file unreadable": {envTONActonBin: bin, envTONActonWorkspace: dir, "HELM_GATEWAY_TON_TESTNET_WALLETS_FILE": filepath.Join(dir, "none")},
	} {
		if _, _, err := tonActonFromEnv(env(m)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	a, w, err := tonActonFromEnv(env(map[string]string{envTONActonBin: bin, envTONActonWorkspace: dir}))
	if err != nil || a == nil || w != nil {
		t.Fatalf("local only: %v %v %v", a, w, err)
	}
	for _, d := range a.Declarations() {
		if d.EffectType == "ton.acton.library.publish_testnet" {
			t.Fatal("testnet operations must not exist without a wallet and an RPC")
		}
	}

	wallets := filepath.Join(dir, "wallets.json")
	secret := filepath.Join(t.TempDir(), "secret")
	_ = os.WriteFile(secret, []byte("x"), 0o600)
	_ = os.WriteFile(wallets, []byte(`{"wallets":[{"tenant_id":"t","wallet_ref":"wallet:a","secret_file":"`+secret+`"}]}`), 0o600)
	inside := filepath.Join(dir, "secret")
	_ = os.WriteFile(inside, []byte("x"), 0o600)
	insideWallets := filepath.Join(t.TempDir(), "w.json")
	_ = os.WriteFile(insideWallets, []byte(`{"wallets":[{"tenant_id":"t","wallet_ref":"wallet:a","secret_file":"`+inside+`"}]}`), 0o600)
	iso := `["/usr/bin/env"]`
	for name, m := range map[string]map[string]string{
		"secret inside the workspace": {envTONActonBin: bin, envTONActonWorkspace: dir, envTONRPCURL: "https://t.example", envTONIsolationCmd: iso, "HELM_GATEWAY_TON_TESTNET_WALLETS_FILE": insideWallets},
		"wallets without isolation":   {envTONActonBin: bin, envTONActonWorkspace: dir, envTONRPCURL: "https://t.example", "HELM_GATEWAY_TON_TESTNET_WALLETS_FILE": wallets},
		"isolation not json":          {envTONActonBin: bin, envTONActonWorkspace: dir, envTONIsolationCmd: "sudo -u x"},
		"isolation relative":          {envTONActonBin: bin, envTONActonWorkspace: dir, envTONIsolationCmd: `["env"]`},
	} {
		if _, _, err := tonActonFromEnv(env(m)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	a, w, err = tonActonFromEnv(env(map[string]string{envTONActonBin: bin, envTONActonWorkspace: dir,
		envTONRPCURL: "https://testnet.toncenter.com/api/v2", envTONIsolationCmd: iso, "HELM_GATEWAY_TON_TESTNET_WALLETS_FILE": wallets}))
	if err != nil || a == nil || w == nil {
		t.Fatalf("full: %v %v %v", a, w, err)
	}
	found := false
	for _, d := range a.Declarations() {
		found = found || d.EffectType == "ton.acton.library.publish_testnet"
	}
	if !found {
		t.Fatal("testnet operations missing with a wallet and an RPC")
	}
}
