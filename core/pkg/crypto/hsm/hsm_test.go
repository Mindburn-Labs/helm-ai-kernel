package hsm

import (
	"context"
	"testing"
)

func TestSoftwareProviderEd25519(t *testing.T) {
	p := NewSoftwareProvider()
	ctx := context.Background()

	if err := p.Open(ctx); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	handle, err := p.GenerateKey(ctx, KeyGenOpts{
		Algorithm: AlgorithmEd25519,
		Label:     "test-key",
		Usage:     KeyUsageSign | KeyUsageVerify,
	})
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("HELM canonical message for signing")

	sig, err := p.Sign(ctx, handle, message, SignOpts{})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("expected 64-byte Ed25519 signature, got %d bytes", len(sig))
	}

	valid, err := p.Verify(ctx, handle, message, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !valid {
		t.Fatal("signature should be valid")
	}

	// Tampered message should not verify
	valid, _ = p.Verify(ctx, handle, []byte("tampered"), sig)
	if valid {
		t.Fatal("tampered message should not verify")
	}
}

func TestSoftwareProviderECDSA(t *testing.T) {
	p := NewSoftwareProvider()
	ctx := context.Background()
	p.Open(ctx)
	defer p.Close()

	handle, err := p.GenerateKey(ctx, KeyGenOpts{
		Algorithm: AlgorithmECDSAP256,
		Label:     "ecdsa-key",
		Usage:     KeyUsageSign | KeyUsageVerify,
	})
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("ECDSA test message")
	sig, err := p.Sign(ctx, handle, message, SignOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty ECDSA signature")
	}

	valid, err := p.Verify(ctx, handle, message, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("ECDSA signature should be valid")
	}
}

func TestSoftwareProviderNotInitialized(t *testing.T) {
	p := NewSoftwareProvider()
	ctx := context.Background()

	_, err := p.GenerateKey(ctx, KeyGenOpts{Algorithm: AlgorithmEd25519})
	if err != ErrNotInitialized {
		t.Fatalf("expected ErrNotInitialized, got %v", err)
	}
}

func TestSoftwareProviderKeyNotFound(t *testing.T) {
	p := NewSoftwareProvider()
	ctx := context.Background()
	p.Open(ctx)
	defer p.Close()

	_, err := p.Sign(ctx, "nonexistent", []byte("msg"), SignOpts{})
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestSoftwareProviderKeyUsageEnforced(t *testing.T) {
	p := NewSoftwareProvider()
	ctx := context.Background()
	p.Open(ctx)
	defer p.Close()

	handle, _ := p.GenerateKey(ctx, KeyGenOpts{
		Algorithm: AlgorithmEd25519,
		Label:     "verify-only",
		Usage:     KeyUsageVerify, // No sign permission
	})

	_, err := p.Sign(ctx, handle, []byte("msg"), SignOpts{})
	if err == nil {
		t.Fatal("expected error for signing with verify-only key")
	}
}

func TestSoftwareProviderListAndDelete(t *testing.T) {
	p := NewSoftwareProvider()
	ctx := context.Background()
	p.Open(ctx)
	defer p.Close()

	h1, _ := p.GenerateKey(ctx, KeyGenOpts{Algorithm: AlgorithmEd25519, Label: "k1", Usage: KeyUsageSign})
	p.GenerateKey(ctx, KeyGenOpts{Algorithm: AlgorithmEd25519, Label: "k2", Usage: KeyUsageSign})

	keys, _ := p.ListKeys(ctx)
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	p.DeleteKey(ctx, h1)
	keys, _ = p.ListKeys(ctx)
	if len(keys) != 1 {
		t.Fatalf("expected 1 key after delete, got %d", len(keys))
	}
}

func TestPKCS11ProviderNotLinked(t *testing.T) {
	_, err := NewPKCS11Provider(PKCS11Config{LibraryPath: "/usr/lib/some.so"})
	if err != ErrPKCS11NotLinked {
		t.Fatalf("expected ErrPKCS11NotLinked, got %v", err)
	}
}
