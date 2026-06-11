package artifacts

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func TestFileStoreCoverage(t *testing.T) {
	ctx := context.Background()
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	data := []byte("artifact")
	hash, err := store.Store(ctx, data)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	hashAgain, err := store.Store(ctx, data)
	if err != nil {
		t.Fatalf("Store existing: %v", err)
	}
	if hashAgain != hash {
		t.Fatalf("hash mismatch: %s != %s", hashAgain, hash)
	}

	got, err := store.Get(ctx, hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("Get returned %q", got)
	}

	exists, err := store.Exists(ctx, hash)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("expected artifact to exist")
	}

	if err := store.Delete(ctx, hash); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Delete(ctx, hash); err != nil {
		t.Fatalf("Delete missing should be ignored: %v", err)
	}

	exists, err = store.Exists(ctx, hash)
	if err != nil {
		t.Fatalf("Exists missing: %v", err)
	}
	if exists {
		t.Fatal("expected artifact to be deleted")
	}
}

func TestFileStoreCoverageErrors(t *testing.T) {
	ctx := context.Background()
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	for _, fn := range []func(string) error{
		func(hash string) error {
			_, err := store.Get(ctx, hash)
			return err
		},
		func(hash string) error {
			_, err := store.Exists(ctx, hash)
			return err
		},
		func(hash string) error {
			return store.Delete(ctx, hash)
		},
	} {
		if err := fn("bad"); err == nil || !strings.Contains(err.Error(), "invalid hash format") {
			t.Fatalf("expected invalid format error, got %v", err)
		}
		if err := fn("sha256:not-hex"); err == nil || !strings.Contains(err.Error(), "invalid hash hex") {
			t.Fatalf("expected invalid hex error, got %v", err)
		}
	}

	missingHash := "sha256:" + strings.Repeat("0", 64)
	if _, err := store.Get(ctx, missingHash); err == nil || !strings.Contains(err.Error(), "artifact not found") {
		t.Fatalf("expected not found, got %v", err)
	}

	restore := replaceFileStoreHooks()
	defer restore()

	sentinel := errors.New("sentinel")
	fileStoreMkdirAll = func(string, os.FileMode) error { return sentinel }
	if _, err := NewFileStore(t.TempDir()); err == nil || !strings.Contains(err.Error(), "failed to ensure artifact dir") {
		t.Fatalf("expected mkdir error, got %v", err)
	}
	restore()

	fileStoreWrite = func(string, []byte, os.FileMode) error { return sentinel }
	if _, err := store.Store(ctx, []byte("write-fail")); err == nil || !strings.Contains(err.Error(), "failed to write blob") {
		t.Fatalf("expected write error, got %v", err)
	}
	restore()

	fileStoreRename = func(string, string) error { return sentinel }
	if _, err := store.Store(ctx, []byte("rename-fail")); err == nil || !strings.Contains(err.Error(), "failed to commit blob") {
		t.Fatalf("expected rename error, got %v", err)
	}
	restore()

	fileStoreOpen = func(string) (*os.File, error) { return nil, sentinel }
	if _, err := store.Get(ctx, missingHash); !errors.Is(err, sentinel) {
		t.Fatalf("expected open sentinel, got %v", err)
	}
	restore()

	fileStoreStat = func(string) (os.FileInfo, error) { return nil, sentinel }
	if _, err := store.Exists(ctx, missingHash); !errors.Is(err, sentinel) {
		t.Fatalf("expected stat sentinel, got %v", err)
	}
	restore()

	fileStoreRemove = func(string) error { return sentinel }
	if err := store.Delete(ctx, missingHash); err == nil || !strings.Contains(err.Error(), "failed to delete artifact") {
		t.Fatalf("expected remove error, got %v", err)
	}
}

func replaceFileStoreHooks() func() {
	originalMkdirAll := fileStoreMkdirAll
	originalStat := fileStoreStat
	originalWrite := fileStoreWrite
	originalRename := fileStoreRename
	originalOpen := fileStoreOpen
	originalRemove := fileStoreRemove
	return func() {
		fileStoreMkdirAll = originalMkdirAll
		fileStoreStat = originalStat
		fileStoreWrite = originalWrite
		fileStoreRename = originalRename
		fileStoreOpen = originalOpen
		fileStoreRemove = originalRemove
	}
}

func TestNewStoreFromEnvS3Success(t *testing.T) {
	restore := replaceS3ConfigLoader()
	defer restore()

	t.Setenv("ARTIFACT_STORAGE_TYPE", "s3")
	t.Setenv("ARTIFACT_S3_BUCKET", "bucket")
	t.Setenv("ARTIFACT_S3_REGION", "eu-test-1")
	t.Setenv("ARTIFACT_S3_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("ARTIFACT_S3_PREFIX", "prefix/")

	store, err := NewStoreFromEnv(context.Background())
	if err != nil {
		t.Fatalf("NewStoreFromEnv: %v", err)
	}
	s3Store, ok := store.(*S3Store)
	if !ok {
		t.Fatalf("expected *S3Store, got %T", store)
	}
	if s3Store.bucket != "bucket" || s3Store.prefix != "prefix/" {
		t.Fatalf("unexpected S3 store config: %#v", s3Store)
	}
}

func TestNewStoreFromEnvDefaultDataDir(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	temp := t.TempDir()
	if err := os.Chdir(temp); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore Chdir: %v", err)
		}
	}()

	t.Setenv("ARTIFACT_STORAGE_TYPE", "fs")
	t.Setenv("DATA_DIR", "")
	store, err := NewStoreFromEnv(context.Background())
	if err != nil {
		t.Fatalf("NewStoreFromEnv: %v", err)
	}
	fileStore, ok := store.(*FileStore)
	if !ok {
		t.Fatalf("expected *FileStore, got %T", store)
	}
	if fileStore.baseDir != filepath.Join("data", "artifacts") {
		t.Fatalf("unexpected baseDir %q", fileStore.baseDir)
	}
}

func TestNewStoreFromEnvS3RegionFallbacks(t *testing.T) {
	restore := replaceS3ConfigLoader()
	defer restore()

	t.Setenv("ARTIFACT_STORAGE_TYPE", "s3")
	t.Setenv("ARTIFACT_S3_BUCKET", "bucket")
	t.Setenv("AWS_REGION", "eu-fallback-1")

	if _, err := NewStoreFromEnv(context.Background()); err != nil {
		t.Fatalf("NewStoreFromEnv AWS_REGION fallback: %v", err)
	}

	t.Setenv("AWS_REGION", "")
	if _, err := NewStoreFromEnv(context.Background()); err != nil {
		t.Fatalf("NewStoreFromEnv default region: %v", err)
	}
}

func TestNewS3StoreConfigErrorAndNoEndpoint(t *testing.T) {
	restore := replaceS3ConfigLoader()
	defer restore()

	store, err := NewS3Store(context.Background(), S3StoreConfig{Bucket: "bucket", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("NewS3Store no endpoint: %v", err)
	}
	if store.bucket != "bucket" {
		t.Fatalf("unexpected bucket %q", store.bucket)
	}

	loadS3DefaultConfig = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, errors.New("load failed")
	}
	if _, err := NewS3Store(context.Background(), S3StoreConfig{}); err == nil || !strings.Contains(err.Error(), "failed to load AWS config") {
		t.Fatalf("expected config load error, got %v", err)
	}
}

func TestS3StoreCoverage(t *testing.T) {
	objects := map[string][]byte{}
	failPut := false
	failDelete := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/bucket/")
		switch r.Method {
		case http.MethodHead:
			if _, ok := objects[key]; ok {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.NotFound(w, r)
		case http.MethodPut:
			if failPut {
				http.Error(w, "put failed", http.StatusInternalServerError)
				return
			}
			body, _ := io.ReadAll(r.Body)
			objects[key] = body
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			body, ok := objects[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(body)
		case http.MethodDelete:
			if failDelete {
				http.Error(w, "delete failed", http.StatusInternalServerError)
				return
			}
			delete(objects, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	restore := replaceS3ConfigLoader()
	defer restore()

	store, err := NewS3Store(context.Background(), S3StoreConfig{
		Bucket:   "bucket",
		Region:   "us-east-1",
		Endpoint: server.URL,
		Prefix:   "prefix/",
	})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}

	data := []byte("s3-artifact")
	hash, err := store.Store(context.Background(), data)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if _, err := store.Store(context.Background(), data); err != nil {
		t.Fatalf("Store existing: %v", err)
	}

	exists, err := store.Exists(context.Background(), hash)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("expected S3 object to exist")
	}
	exists, err = store.Exists(context.Background(), "sha256:"+strings.Repeat("0", 64))
	if err != nil {
		t.Fatalf("Exists missing: %v", err)
	}
	if exists {
		t.Fatal("expected missing object")
	}

	got, err := store.Get(context.Background(), hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("Get returned %q", got)
	}

	if err := store.Delete(context.Background(), hash); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := store.Get(context.Background(), hash); err == nil || !strings.Contains(err.Error(), "s3 get failed") {
		t.Fatalf("expected get error, got %v", err)
	}
	if _, err := store.Get(context.Background(), "bad"); err == nil || !strings.Contains(err.Error(), "invalid hash format") {
		t.Fatalf("expected invalid get hash, got %v", err)
	}
	if _, err := store.Exists(context.Background(), "bad"); err == nil || !strings.Contains(err.Error(), "invalid hash format") {
		t.Fatalf("expected invalid exists hash, got %v", err)
	}
	if err := store.Delete(context.Background(), "bad"); err == nil || !strings.Contains(err.Error(), "invalid hash format") {
		t.Fatalf("expected invalid delete hash, got %v", err)
	}

	failPut = true
	if _, err := store.Store(context.Background(), []byte("put-fail")); err == nil || !strings.Contains(err.Error(), "s3 put failed") {
		t.Fatalf("expected put error, got %v", err)
	}
	failPut = false

	hash, err = store.Store(context.Background(), []byte("delete-fail"))
	if err != nil {
		t.Fatalf("Store before delete error: %v", err)
	}
	failDelete = true
	if err := store.Delete(context.Background(), hash); err == nil || !strings.Contains(err.Error(), "s3 delete failed") {
		t.Fatalf("expected delete error, got %v", err)
	}
}

func replaceS3ConfigLoader() func() {
	original := loadS3DefaultConfig
	loadS3DefaultConfig = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{
			Region:      "us-east-1",
			Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("id", "secret", "")),
		}, nil
	}
	return func() { loadS3DefaultConfig = original }
}

func TestRegistryCoverage(t *testing.T) {
	ctx := context.Background()
	store := &memoryStore{objects: map[string][]byte{}}
	registry := NewRegistry(store, nil)

	for name, envelope := range map[string]*ArtifactEnvelope{
		"nil":             nil,
		"missing type":    {Payload: json.RawMessage(`{"ok":true}`)},
		"missing payload": {Type: TypeAlertEvidence},
		"too large":       {Type: TypeAlertEvidence, Payload: bytes.Repeat([]byte("x"), 10*1024*1024+1)},
		"bad json":        {Type: TypeAlertEvidence, Payload: json.RawMessage(`{`)},
	} {
		if _, err := registry.PutArtifact(ctx, envelope); err == nil {
			t.Fatalf("%s: expected PutArtifact error", name)
		}
	}

	store.err = errors.New("store failed")
	if _, err := registry.PutArtifact(ctx, testEnvelope()); !errors.Is(err, store.err) {
		t.Fatalf("expected store error, got %v", err)
	}
	store.err = nil

	hash, err := registry.PutArtifact(ctx, testEnvelope())
	if err != nil {
		t.Fatalf("PutArtifact: %v", err)
	}
	got, err := registry.GetArtifact(ctx, hash)
	if err != nil {
		t.Fatalf("GetArtifact: %v", err)
	}
	if got.Type != TypeAlertEvidence {
		t.Fatalf("unexpected envelope: %#v", got)
	}

	store.objects["corrupt"] = []byte("{")
	if _, err := registry.GetArtifact(ctx, "corrupt"); err == nil || !strings.Contains(err.Error(), "corrupt artifact data") {
		t.Fatalf("expected corrupt artifact error, got %v", err)
	}
	if _, err := registry.GetArtifact(ctx, "missing"); err == nil {
		t.Fatal("expected missing artifact error")
	}
	if _, _, err := registry.VerifyArtifact(ctx, "missing"); err == nil {
		t.Fatal("expected verify missing artifact error")
	}

	store.objects["missing-type"] = mustJSON(t, &ArtifactEnvelope{Payload: json.RawMessage(`{"ok":true}`)})
	valid, reasons, err := registry.VerifyArtifact(ctx, "missing-type")
	if err != nil {
		t.Fatalf("VerifyArtifact missing type: %v", err)
	}
	if valid || len(reasons) == 0 || reasons[0] != "missing type" {
		t.Fatalf("expected missing type reason, got valid=%v reasons=%v", valid, reasons)
	}

	store.objects["unsigned"] = mustJSON(t, testEnvelope())
	valid, reasons, err = registry.VerifyArtifact(ctx, "unsigned")
	if err != nil {
		t.Fatalf("VerifyArtifact unsigned: %v", err)
	}
	if valid || len(reasons) == 0 || reasons[0] != "missing signature or key_id" {
		t.Fatalf("expected unsigned reason, got valid=%v reasons=%v", valid, reasons)
	}

	env := testEnvelope()
	env.Signature = hex.EncodeToString([]byte("sig"))
	env.SignatureKeyID = "key"
	store.objects["no-verifier"] = mustJSON(t, env)
	valid, reasons, err = registry.VerifyArtifact(ctx, "no-verifier")
	if err != nil {
		t.Fatalf("VerifyArtifact no verifier: %v", err)
	}
	if valid || !containsReason(reasons, "artifact signature verifier not configured (fail-closed)") {
		t.Fatalf("expected verifier missing reason, got valid=%v reasons=%v", valid, reasons)
	}

	env.Signature = "not-hex"
	store.objects["bad-signature"] = mustJSON(t, env)
	valid, reasons, err = NewRegistry(store, verifierFunc(func([]byte, []byte) bool { return true })).VerifyArtifact(ctx, "bad-signature")
	if err != nil {
		t.Fatalf("VerifyArtifact bad signature: %v", err)
	}
	if valid || !containsReason(reasons, "signature decode failed") {
		t.Fatalf("expected signature decode reason, got valid=%v reasons=%v", valid, reasons)
	}

	env.Signature = "hex:" + hex.EncodeToString([]byte("sig"))
	store.objects["invalid-signature"] = mustJSON(t, env)
	valid, reasons, err = NewRegistry(store, verifierFunc(func([]byte, []byte) bool { return false })).VerifyArtifact(ctx, "invalid-signature")
	if err != nil {
		t.Fatalf("VerifyArtifact invalid signature: %v", err)
	}
	if valid || !containsReason(reasons, "signature invalid") {
		t.Fatalf("expected invalid signature reason, got valid=%v reasons=%v", valid, reasons)
	}

	valid, reasons, err = NewRegistry(store, verifierFunc(func([]byte, []byte) bool { return true })).VerifyArtifact(ctx, "invalid-signature")
	if err != nil {
		t.Fatalf("VerifyArtifact valid: %v", err)
	}
	if !valid || len(reasons) != 0 {
		t.Fatalf("expected valid artifact, got valid=%v reasons=%v", valid, reasons)
	}
}

func TestSignEnvelopeCoverage(t *testing.T) {
	if err := SignEnvelope(nil, nil); err == nil || !strings.Contains(err.Error(), "nil envelope") {
		t.Fatalf("expected nil envelope error, got %v", err)
	}
	if err := SignEnvelope(testEnvelope(), nil); !errors.Is(err, ErrSignerNotConfigured) {
		t.Fatalf("expected signer error, got %v", err)
	}
	if err := SignEnvelope(&ArtifactEnvelope{}, errorSigner{}); err == nil || !strings.Contains(err.Error(), "missing payload") {
		t.Fatalf("expected missing payload error, got %v", err)
	}
	if err := SignEnvelope(testEnvelope(), errorSigner{}); err == nil || !strings.Contains(err.Error(), "sign failed") {
		t.Fatalf("expected sign failed error, got %v", err)
	}

	signer, err := helmcrypto.NewEd25519Signer("key")
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	env := testEnvelope()
	if err := SignEnvelope(env, signer); err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	if env.Signature == "" || env.SignatureKeyID == "" {
		t.Fatalf("signature metadata was not populated: %#v", env)
	}
}

func TestRegistryVerifyArtifactRejectsEnvelopeMetadataTamper(t *testing.T) {
	ctx := context.Background()
	signer, err := helmcrypto.NewEd25519Signer("artifact-key")
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	verifier, err := helmcrypto.NewEd25519Verifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatalf("NewEd25519Verifier: %v", err)
	}

	store := &memoryStore{objects: map[string][]byte{}}
	registry := NewRegistry(store, verifier)
	env := testEnvelope()
	if err := SignEnvelope(env, signer); err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	store.objects["signed"] = mustJSON(t, env)

	valid, reasons, err := registry.VerifyArtifact(ctx, "signed")
	if err != nil {
		t.Fatalf("VerifyArtifact signed: %v", err)
	}
	if !valid || len(reasons) != 0 {
		t.Fatalf("expected signed artifact to verify, got valid=%v reasons=%v", valid, reasons)
	}

	for name, mutate := range map[string]func(*ArtifactEnvelope){
		"type":           func(e *ArtifactEnvelope) { e.Type = TypeVerificationRecord },
		"schema_version": func(e *ArtifactEnvelope) { e.SchemaVersion = "v2" },
		"producer_id":    func(e *ArtifactEnvelope) { e.ProducerID = "other-producer" },
		"timestamp":      func(e *ArtifactEnvelope) { e.Timestamp = e.Timestamp.Add(time.Second) },
		"payload":        func(e *ArtifactEnvelope) { e.Payload = json.RawMessage(`{"ok":false}`) },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := *env
			mutate(&tampered)
			store.objects["tampered"] = mustJSON(t, &tampered)
			valid, reasons, err := registry.VerifyArtifact(ctx, "tampered")
			if err != nil {
				t.Fatalf("VerifyArtifact tampered: %v", err)
			}
			if valid || !containsReason(reasons, "signature invalid") {
				t.Fatalf("expected signature invalid for %s tamper, got valid=%v reasons=%v", name, valid, reasons)
			}
		})
	}
}

type memoryStore struct {
	objects map[string][]byte
	err     error
}

func (s *memoryStore) Store(_ context.Context, data []byte) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	hash := "mem:" + hex.EncodeToString(data)
	s.objects[hash] = append([]byte(nil), data...)
	return hash, nil
}

func (s *memoryStore) Get(_ context.Context, hash string) ([]byte, error) {
	data, ok := s.objects[hash]
	if !ok {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func (s *memoryStore) Exists(_ context.Context, hash string) (bool, error) {
	_, ok := s.objects[hash]
	return ok, nil
}

func (s *memoryStore) Delete(_ context.Context, hash string) error {
	delete(s.objects, hash)
	return nil
}

type verifierFunc func([]byte, []byte) bool

func (f verifierFunc) Verify(message []byte, signature []byte) bool {
	return f(message, signature)
}

func (f verifierFunc) VerifyDecision(*contracts.DecisionRecord) (bool, error) {
	return false, nil
}

func (f verifierFunc) VerifyIntent(*contracts.AuthorizedExecutionIntent) (bool, error) {
	return false, nil
}

func (f verifierFunc) VerifyReceipt(*contracts.Receipt) (bool, error) {
	return false, nil
}

type errorSigner struct{}

func (errorSigner) Sign([]byte) (string, error) {
	return "", errors.New("signer failed")
}

func (errorSigner) PublicKey() string {
	return "key"
}

func (errorSigner) PublicKeyBytes() []byte {
	return nil
}

func (errorSigner) SignDecision(*contracts.DecisionRecord) error {
	return nil
}

func (errorSigner) SignIntent(*contracts.AuthorizedExecutionIntent) error {
	return nil
}

func (errorSigner) SignReceipt(*contracts.Receipt) error {
	return nil
}

func testEnvelope() *ArtifactEnvelope {
	return &ArtifactEnvelope{
		Type:          TypeAlertEvidence,
		SchemaVersion: "v1",
		ProducerID:    "test",
		Timestamp:     time.Unix(100, 0),
		Payload:       json.RawMessage(`{"ok":true}`),
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

func containsReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func TestNewFileStoreMkdirRealError(t *testing.T) {
	parent := t.TempDir()
	filePath := filepath.Join(parent, "file")
	if err := os.WriteFile(filePath, []byte("not a dir"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := NewFileStore(filepath.Join(filePath, "child")); err == nil {
		t.Fatal("expected mkdir error")
	}
}
