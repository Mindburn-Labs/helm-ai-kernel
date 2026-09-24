package kms

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// 16-02: importing the legacy env key on boot must not re-pin it as the
// active version, or every restart silently reverts a rotation.
func TestImportKeyDoesNotRepinActiveVersion(t *testing.T) {
	path := tempKeystore(t)
	k, err := NewLocalKMS(path)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := k.Rotate(); err != nil || v != 2 {
		t.Fatalf("Rotate = %d, %v; want 2", v, err)
	}

	if err := k.ImportKey(bytes.Repeat([]byte{7}, 32), 0); err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	if got := k.ActiveVersion(); got != 2 {
		t.Fatalf("ImportKey re-pinned the active version: got %d, want 2", got)
	}

	reloaded, err := NewLocalKMS(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.ActiveVersion(); got != 2 {
		t.Fatalf("reloaded active version = %d, want 2", got)
	}
}

// 16-02: a second import under an existing version must never replace the
// stored key; that would make every ciphertext under it undecryptable.
func TestImportKeyNeverOverwritesStoredVersion(t *testing.T) {
	k, err := NewLocalKMS(tempKeystore(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.ImportKey(bytes.Repeat([]byte{1}, 32), 1); err == nil {
		t.Fatal("ImportKey replaced the stored v1 key")
	}
	if err := k.ImportKey(bytes.Repeat([]byte{2}, 32), 0); err != nil {
		t.Fatalf("first import of v0: %v", err)
	}
	if err := k.ImportKey(bytes.Repeat([]byte{2}, 32), 0); err != nil {
		t.Fatalf("re-importing the same v0 key must be a no-op: %v", err)
	}
	if err := k.ImportKey(bytes.Repeat([]byte{3}, 32), 0); err == nil {
		t.Fatal("ImportKey replaced the stored v0 key with a different one")
	}
}

// 16-02 (VD PoC): after ImportKey(…, 0), Rotate computed ActiveVersion+1 = 1
// and overwrote the auto-generated v1, destroying every v1 ciphertext.
func TestRotateAfterImportKeepsExistingVersions(t *testing.T) {
	path := tempKeystore(t)
	k, err := NewLocalKMS(path)
	if err != nil {
		t.Fatal(err)
	}
	ctV1 := mustEncrypt(t, k, "written-before-env-var", testBinding)

	if err := k.ImportKey(bytes.Repeat([]byte{9}, 32), 0); err != nil {
		t.Fatal(err)
	}
	v, err := k.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if v != 2 {
		t.Fatalf("Rotate reused an existing version: got %d, want 2", v)
	}
	if got := mustDecrypt(t, k, ctV1, testBinding); got != "written-before-env-var" {
		t.Fatalf("v1 ciphertext after rotate = %q", got)
	}
}

// 16-14(a): the keystore is replaced by rename, never truncated in place. A
// hard link to the old file keeps the old bytes only if the write replaced
// the inode; an in-place os.WriteFile would change both names at once.
func TestPersistReplacesKeystoreAtomically(t *testing.T) {
	path := tempKeystore(t)
	k, err := NewLocalKMS(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := path + ".before"
	if err := os.Link(path, snapshot); err != nil {
		t.Skipf("hard links unsupported here: %v", err)
	}

	if _, err := k.Rotate(); err != nil {
		t.Fatal(err)
	}

	old, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(old, before) {
		t.Fatal("keystore was rewritten in place; a crash mid-write would truncate it")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if name := e.Name(); name != filepath.Base(path) && name != filepath.Base(snapshot) {
			t.Fatalf("persist left a stray file behind: %s", name)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("keystore mode = %o, want 600", perm)
	}
}

// 16-14: a keystore any local user can read or replace is not a secret.
func TestLoadRefusesWorldAccessibleKeystore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	path := tempKeystore(t)
	if _, err := NewLocalKMS(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalKMS(path); err == nil {
		t.Fatal("loaded a world-readable keystore")
	}
}

// §10.3: rotation is exercised end to end in CI — rotate, verify old,
// verify new, revoke — and survives a restart.
func TestRotationLifecycle(t *testing.T) {
	path := tempKeystore(t)
	k, err := NewLocalKMS(path)
	if err != nil {
		t.Fatal(err)
	}
	ctOld := mustEncrypt(t, k, "sealed-under-v1", testBinding)

	// Rotate.
	if v, err := k.Rotate(); err != nil || v != 2 {
		t.Fatalf("Rotate = %d, %v; want 2", v, err)
	}

	// Verify old: still opens, and is flagged for re-sealing.
	if got := mustDecrypt(t, k, ctOld, testBinding); got != "sealed-under-v1" {
		t.Fatalf("old ciphertext = %q", got)
	}
	if !k.NeedsRewrap(ctOld) {
		t.Fatal("v1 ciphertext not flagged for rewrap after rotation")
	}

	// Verify new.
	ctNew := mustEncrypt(t, k, "sealed-under-v2", testBinding)
	if !strings.HasPrefix(ctNew, "aad1:v2:") {
		t.Fatalf("new ciphertext = %q, want aad1:v2: prefix", ctNew)
	}
	if got := mustDecrypt(t, k, ctNew, testBinding); got != "sealed-under-v2" || k.NeedsRewrap(ctNew) {
		t.Fatalf("new ciphertext = %q needsRewrap=%v", got, k.NeedsRewrap(ctNew))
	}

	// Revoke.
	if err := k.Revoke(2); err == nil {
		t.Fatal("revoked the active version")
	}
	if err := k.Revoke(1); err != nil {
		t.Fatalf("Revoke(1): %v", err)
	}
	if _, err := k.Decrypt(ctOld, testBinding); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("revoked ciphertext: err = %v, want ErrKeyRevoked", err)
	}
	if got := mustDecrypt(t, k, ctNew, testBinding); got != "sealed-under-v2" {
		t.Fatalf("new ciphertext after revoke = %q", got)
	}

	// Revocation is durable and sticky.
	k, err = NewLocalKMS(path)
	if err != nil {
		t.Fatal(err)
	}
	if active, usable, revoked := k.KeyVersions(); active != 2 || !slices.Equal(usable, []int{2}) || !slices.Equal(revoked, []int{1}) {
		t.Fatalf("after reload: active=%d usable=%v revoked=%v", active, usable, revoked)
	}
	if _, err := k.Decrypt(ctOld, testBinding); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("revoked ciphertext after reload: err = %v", err)
	}
	if err := k.ImportKey(bytes.Repeat([]byte{4}, 32), 1); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("re-importing a revoked version: err = %v, want ErrKeyRevoked", err)
	}
	if err := k.Revoke(1); err != nil {
		t.Fatalf("revoking twice must be a no-op: %v", err)
	}
	if err := k.Revoke(99); err == nil {
		t.Fatal("revoked an unknown version")
	}
	if v, err := k.Rotate(); err != nil || v != 3 {
		t.Fatalf("Rotate after revoke = %d, %v; want 3 (never reuse a number)", v, err)
	}
}

// 16-14(b), §10.3: AAD is (tenant, connection, key version).
func TestCiphertextIsBoundToTenantConnectionAndVersion(t *testing.T) {
	k, err := NewLocalKMS(tempKeystore(t))
	if err != nil {
		t.Fatal(err)
	}
	ct := mustEncrypt(t, k, "sk-tenant-a", testBinding)

	for name, b := range map[string]Binding{
		"other tenant":     {Tenant: "tenant-b", Connection: testBinding.Connection},
		"other connection": {Tenant: testBinding.Tenant, Connection: "openai/access_token"},
		"other field":      {Tenant: testBinding.Tenant, Connection: "anthropic/refresh_token"},
	} {
		if pt, err := k.Decrypt(ct, b); err == nil {
			t.Fatalf("%s: decrypted %q", name, pt)
		}
	}

	// Length-prefixed fields: ("ab","c") and ("a","bc") are different bindings.
	split := mustEncrypt(t, k, "x", Binding{Tenant: "ab", Connection: "c"})
	if _, err := k.Decrypt(split, Binding{Tenant: "a", Connection: "bc"}); err == nil {
		t.Fatal("binding fields are ambiguous")
	}

	// The version is authenticated, and a bound ciphertext cannot be
	// downgraded to the legacy unbound form.
	if _, err := k.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Decrypt(strings.Replace(ct, "aad1:v1:", "aad1:v2:", 1), testBinding); err == nil {
		t.Fatal("relabelled key version decrypted")
	}
	if _, err := k.Decrypt(strings.TrimPrefix(ct, "aad1:"), testBinding); err == nil {
		t.Fatal("bound ciphertext decrypted as legacy unbound data")
	}

	if _, err := k.Encrypt("x", Binding{Tenant: "tenant-a"}); err == nil {
		t.Fatal("encrypted without a connection binding")
	}
	if _, err := k.Decrypt(ct, Binding{}); err == nil {
		t.Fatal("decrypted without a binding")
	}
}

// Rows written before AAD binding stay readable, and are flagged so the
// credential store re-seals them.
func TestLegacyUnboundCiphertextStillOpens(t *testing.T) {
	k, err := NewLocalKMS(tempKeystore(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := aesGCMEncrypt(k.keys[1], []byte("legacy-row"), nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy := "v1:" + base64.StdEncoding.EncodeToString(raw)

	if got := mustDecrypt(t, k, legacy, testBinding); got != "legacy-row" {
		t.Fatalf("legacy ciphertext = %q", got)
	}
	if !k.NeedsRewrap(legacy) {
		t.Fatal("legacy unbound ciphertext not flagged for rewrap")
	}
}

// A deployment that still sets CREDENTIALS_ENCRYPTION_KEY: a new keystore
// starts from it, an existing one keeps its active version.
func TestNewLocalKMSWithLegacyKey(t *testing.T) {
	legacy := bytes.Repeat([]byte{5}, 32)

	fresh := tempKeystore(t)
	k, err := NewLocalKMSWithLegacyKey(fresh, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if active, usable, _ := k.KeyVersions(); active != 0 || !slices.Equal(usable, []int{0}) {
		t.Fatalf("fresh keystore: active=%d usable=%v, want only v0", active, usable)
	}

	existing := tempKeystore(t)
	k, err = NewLocalKMS(existing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Rotate(); err != nil {
		t.Fatal(err)
	}
	for boot := 0; boot < 2; boot++ {
		k, err = NewLocalKMSWithLegacyKey(existing, legacy)
		if err != nil {
			t.Fatal(err)
		}
		if got := k.ActiveVersion(); got != 2 {
			t.Fatalf("boot %d re-pinned the legacy key: active = %d", boot, got)
		}
	}
	if err := k.Revoke(0); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalKMSWithLegacyKey(existing, legacy); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("revoked legacy key came back: err = %v", err)
	}
}
