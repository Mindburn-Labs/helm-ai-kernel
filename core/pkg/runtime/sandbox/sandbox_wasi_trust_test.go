package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

type fakeArtifactStore struct {
	data []byte
	gets int
}

func (s *fakeArtifactStore) Store(context.Context, []byte) (string, error) {
	return "", errors.New("not implemented")
}

func (s *fakeArtifactStore) Get(context.Context, string) ([]byte, error) {
	s.gets++
	return s.data, nil
}

func (s *fakeArtifactStore) Exists(context.Context, string) (bool, error) {
	return false, errors.New("not implemented")
}

func (s *fakeArtifactStore) Delete(context.Context, string) error {
	return errors.New("not implemented")
}

type fakePackVerifier struct {
	err   error
	calls int
}

func (v *fakePackVerifier) ValidatePackLoad(trust.PackRef) error {
	v.calls++
	return v.err
}

func TestWasiSandboxRejectsMissingPackVerifierBeforeBlobLoad(t *testing.T) {
	store := &fakeArtifactStore{data: []byte("module")}
	sb := &WasiSandbox{artStore: store}

	_, err := sb.Run(context.Background(), trust.PackRef{
		Name:    "org.example/pack",
		Version: "1.0.0",
		Hash:    "sha256:" + strings.Repeat("0", sha256.Size*2),
	}, nil)
	if err == nil {
		t.Fatal("expected missing pack verifier to fail closed")
	}
	if se, ok := err.(*SandboxError); !ok || se.Code != ErrPackTrustUnverified {
		t.Fatalf("error = %#v, want %s", err, ErrPackTrustUnverified)
	}
	if store.gets != 0 {
		t.Fatalf("artifact store reads = %d, want 0 before trust verification", store.gets)
	}
}

func TestWasiSandboxRejectsFailedPackVerificationBeforeBlobLoad(t *testing.T) {
	store := &fakeArtifactStore{data: []byte("module")}
	verifier := &fakePackVerifier{err: errors.New("TUF target mismatch")}
	sb := &WasiSandbox{artStore: store, packVerifier: verifier}

	_, err := sb.Run(context.Background(), trust.PackRef{
		Name:    "org.example/pack",
		Version: "1.0.0",
		Hash:    "sha256:" + strings.Repeat("0", sha256.Size*2),
	}, nil)
	if err == nil {
		t.Fatal("expected failed pack verifier to fail closed")
	}
	if verifier.calls != 1 {
		t.Fatalf("verifier calls = %d, want 1", verifier.calls)
	}
	if store.gets != 0 {
		t.Fatalf("artifact store reads = %d, want 0 after failed trust verification", store.gets)
	}
	if se, ok := err.(*SandboxError); !ok || se.Code != ErrPackTrustUnverified {
		t.Fatalf("error = %#v, want %s", err, ErrPackTrustUnverified)
	}
}

func TestWasiSandboxVerifiesRetrievedBlobHashBeforeCompile(t *testing.T) {
	store := &fakeArtifactStore{data: []byte("not the trusted module")}
	verifier := &fakePackVerifier{}
	sb := &WasiSandbox{artStore: store, packVerifier: verifier}

	trustedBytes := []byte("trusted module")
	trustedHash := sha256.Sum256(trustedBytes)
	_, err := sb.Run(context.Background(), trust.PackRef{
		Name:    "org.example/pack",
		Version: "1.0.0",
		Hash:    "sha256:" + hex.EncodeToString(trustedHash[:]),
	}, nil)
	if err == nil {
		t.Fatal("expected blob hash mismatch before WASM compile")
	}
	if verifier.calls != 1 {
		t.Fatalf("verifier calls = %d, want 1", verifier.calls)
	}
	if store.gets != 1 {
		t.Fatalf("artifact store reads = %d, want 1 after trust verification", store.gets)
	}
	if se, ok := err.(*SandboxError); !ok || se.Code != ErrPackHashMismatch {
		t.Fatalf("error = %#v, want %s", err, ErrPackHashMismatch)
	}
}
