package credentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kms"
)

func newKMSStore(t *testing.T) (*Store, *sql.DB, *kms.LocalKMS) {
	t.Helper()
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	k, err := kms.NewLocalKMS(filepath.Join(t.TempDir(), "keys", "credentials.keystore.json"))
	if err != nil {
		t.Fatal(err)
	}
	return NewStoreWithKMS(db, k), db, k
}

func storedAccessToken(t *testing.T, db *sql.DB, operatorID string, provider ProviderType) string {
	t.Helper()
	var ct string
	if err := db.QueryRow(`SELECT access_token FROM credentials WHERE operator_id = $1 AND provider = $2`, operatorID, provider).Scan(&ct); err != nil {
		t.Fatal(err)
	}
	return ct
}

// 16-14(b): a ciphertext copied into another operator's row must not decrypt
// there. Before AAD binding, operator B silently received operator A's key.
func TestCiphertextMovedToAnotherRowIsRejected(t *testing.T) {
	store, db, _ := newKMSStore(t)
	ctx := context.Background()
	for _, c := range []*Credential{
		{ID: "a", OperatorID: "operator-a", Provider: ProviderAnthropic, TokenType: TokenTypeApiKey, AccessToken: "sk-operator-a"},
		{ID: "b", OperatorID: "operator-b", Provider: ProviderAnthropic, TokenType: TokenTypeApiKey, AccessToken: "sk-operator-b"},
		{ID: "c", OperatorID: "operator-a", Provider: ProviderOpenAI, TokenType: TokenTypeApiKey, AccessToken: "sk-openai-a"},
	} {
		if err := store.SaveCredential(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	stolen := storedAccessToken(t, db, "operator-a", ProviderAnthropic)
	if _, err := db.Exec(`UPDATE credentials SET access_token = $1 WHERE operator_id = 'operator-b'`, stolen); err != nil {
		t.Fatal(err)
	}
	if cred, err := store.GetCredential(ctx, "operator-b", ProviderAnthropic); err == nil {
		t.Fatalf("another tenant's ciphertext decrypted: %q", cred.AccessToken)
	}

	// Same tenant, other connection: still a different binding.
	if _, err := db.Exec(`UPDATE credentials SET access_token = $1 WHERE operator_id = 'operator-a' AND provider = 'openai'`, stolen); err != nil {
		t.Fatal(err)
	}
	if cred, err := store.GetCredential(ctx, "operator-a", ProviderOpenAI); err == nil {
		t.Fatalf("another connection's ciphertext decrypted: %q", cred.AccessToken)
	}
}

// 12-07: an operator with no stored credential must not inherit the server's
// own provider key from the environment.
func TestMissingCredentialDoesNotFallBackToServerEnv(t *testing.T) {
	store, _, _ := newKMSStore(t)
	t.Setenv("ANTHROPIC_API_KEY", "sk-server-own-key")
	t.Setenv("OPENAI_API_KEY", "sk-server-own-key")
	t.Setenv("GEMINI_API_KEY", "server-own-key")
	ctx := context.Background()

	cred, err := store.GetCredential(ctx, "operator-without-rows", ProviderAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	if cred != nil {
		t.Fatalf("operator received the server's env credential: %+v", cred)
	}
	statuses, err := store.GetStatus(ctx, "operator-without-rows")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range statuses {
		if s.Connected {
			t.Fatalf("%s reported connected from the server environment", s.Provider)
		}
	}
}

// legacySeal produces a row as written before AAD binding: "v<N>:" plus
// AES-256-GCM with no additional data, under the keystore's version N key.
func legacySeal(t *testing.T, keystorePath string, version int, plaintext string) string {
	t.Helper()
	raw, err := os.ReadFile(keystorePath)
	if err != nil {
		t.Fatal(err)
	}
	var ks kms.Keystore
	if err := json.Unmarshal(raw, &ks); err != nil {
		t.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(ks.Keys[strconv.Itoa(version)])
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	return fmt.Sprintf("v%d:%s", version, base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plaintext), nil)))
}

// Reading a row re-seals it under the active key with its binding, so
// legacy unbound rows gain AAD and a rotation reaches stored data before the
// old version is revoked.
func TestReadResealsLegacyAndRotatedRows(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	path := filepath.Join(t.TempDir(), "keys", "credentials.keystore.json")
	k, err := kms.NewLocalKMS(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithKMS(db, k)
	ctx := context.Background()

	if _, err := db.Exec(`INSERT INTO credentials (id, operator_id, provider, token_type, access_token) VALUES ('legacy', 'op', 'anthropic', 'apikey', $1)`,
		legacySeal(t, path, 1, "sk-legacy")); err != nil {
		t.Fatal(err)
	}
	read := func() {
		t.Helper()
		cred, err := store.GetCredential(ctx, "op", ProviderAnthropic)
		if err != nil || cred == nil || cred.AccessToken != "sk-legacy" {
			t.Fatalf("GetCredential = %+v, %v", cred, err)
		}
	}

	read()
	if got := storedAccessToken(t, db, "op", ProviderAnthropic); !strings.HasPrefix(got, "aad1:v1:") {
		t.Fatalf("legacy row not re-sealed with its binding: %q", got)
	}

	if _, err := k.Rotate(); err != nil {
		t.Fatal(err)
	}
	read()
	if got := storedAccessToken(t, db, "op", ProviderAnthropic); !strings.HasPrefix(got, "aad1:v2:") {
		t.Fatalf("row not re-sealed under the rotated key: %q", got)
	}

	if err := k.Revoke(1); err != nil {
		t.Fatal(err)
	}
	read()
}
