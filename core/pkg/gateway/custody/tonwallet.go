package custody

// quantum_posture: the testnet wallet secret is an opaque string read from a
// mounted file; nothing here signs, verifies or negotiates a key exchange, and
// no post-quantum claim is made.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// EnvTONWalletsFile names the wallets file: tenant, wallet_ref and the file that
// holds each testnet secret. The operator provides both; the chart does not yet.
const EnvTONWalletsFile = "HELM_GATEWAY_TON_TESTNET_WALLETS_FILE"

const tonActonPrefix = "ton.acton."

// maxWalletSecretBytes bounds a secret file: a mnemonic is a few hundred bytes.
const maxWalletSecretBytes = 4096

// TONWallet is one entry of the wallets file: the opaque wallet_ref a tenant's
// effect names, and the file that holds its testnet secret.
type TONWallet struct {
	TenantID   string `json:"tenant_id"`
	WalletRef  string `json:"wallet_ref"`
	SecretFile string `json:"secret_file"`
}

// TONWallets is the connection custody of the gateway's TON testnet wallets. A
// tenant gets a secret only for a wallet_ref its entry lists; the secret is read
// from its file on every call and kept nowhere.
type TONWallets struct {
	by map[[2]string]string
}

// NewTONWallets parses the wallets file and refuses a malformed one.
func NewTONWallets(wallets []byte) (*TONWallets, error) {
	var file struct {
		Wallets []TONWallet `json:"wallets"`
	}
	dec := json.NewDecoder(bytes.NewReader(wallets))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("the TON wallets file: %w", err)
	}
	if len(file.Wallets) == 0 {
		return nil, errors.New("the TON wallets file lists no wallet")
	}
	w := &TONWallets{by: map[[2]string]string{}}
	for i, e := range file.Wallets {
		key := [2]string{e.TenantID, e.WalletRef}
		switch {
		case e.TenantID == "" || !strings.HasPrefix(e.WalletRef, "wallet:") || e.SecretFile == "":
			return nil, fmt.Errorf("wallet %d needs tenant_id, a wallet: wallet_ref and secret_file", i)
		case w.by[key] != "":
			return nil, fmt.Errorf("wallet %d repeats tenant %q and %q", i, e.TenantID, e.WalletRef)
		}
		w.by[key] = e.SecretFile
	}
	return w, nil
}

// TONWalletsFromEnv reads the wallets file the environment names; unset returns nil.
func TONWalletsFromEnv(getenv func(string) string) (*TONWallets, error) {
	path := strings.TrimSpace(getenv(EnvTONWalletsFile))
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path) // #nosec G304 -- operator-configured secret mount path
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvTONWalletsFile, err)
	}
	return NewTONWallets(b)
}

// SecretFiles lists the secret files the wallets file names.
func (w *TONWallets) SecretFiles() []string {
	out := make([]string, 0, len(w.by))
	for _, f := range w.by {
		out = append(out, f)
	}
	return out
}

// Token returns the testnet wallet secret for one TON effect of one tenant. The
// wallet_ref is read from the effect's arguments, which the permit's digest
// binds, and is only a lookup key.
func (w *TONWallets) Token(_ context.Context, tenantID string, effect adapters.Effect) (string, error) {
	if !strings.HasPrefix(effect.EffectType, tonActonPrefix) {
		return "", errors.New("custody: not a TON effect")
	}
	var args struct {
		WalletRef string `json:"wallet_ref"`
	}
	if json.Unmarshal(effect.Arguments, &args) != nil || args.WalletRef == "" {
		return "", errors.New("custody: the effect names no wallet_ref")
	}
	path, ok := w.by[[2]string{tenantID, args.WalletRef}]
	if !ok {
		return "", errors.New("custody: no testnet wallet for this tenant and wallet_ref")
	}
	f, err := os.Open(path) // #nosec G304 -- operator-configured secret mount path
	if err != nil {
		return "", errors.New("custody: the wallet secret is not readable")
	}
	defer func() { _ = f.Close() }()
	// A secret that group or others can read is readable by whatever runs Acton
	// under another account; the file must be the gateway's alone.
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("custody: the wallet secret file must be a regular file readable by its owner only")
	}
	buf := make([]byte, maxWalletSecretBytes+1)
	n, _ := f.Read(buf)
	secret := strings.TrimSpace(string(buf[:n]))
	if n > maxWalletSecretBytes || secret == "" {
		return "", errors.New("custody: the wallet secret file is empty or too large")
	}
	return secret, nil
}

// Source is a connection custody, as admission.Credentials.
type Source interface {
	Token(ctx context.Context, tenantID string, effect adapters.Effect) (string, error)
}

// Routed sends a TON effect to the wallet custody and every other effect to
// the default (GitHub) custody. A custody left nil answers with an error.
type Routed struct {
	Default, TON Source
}

// Token implements the custody interface.
func (r Routed) Token(ctx context.Context, tenantID string, effect adapters.Effect) (string, error) {
	src := r.Default
	if strings.HasPrefix(effect.EffectType, tonActonPrefix) {
		src = r.TON
	}
	if src == nil {
		return "", errors.New("custody: no credential source for this effect type")
	}
	return src.Token(ctx, tenantID, effect)
}
