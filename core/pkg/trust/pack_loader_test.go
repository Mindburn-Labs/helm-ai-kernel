package trust

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
)

func TestNewPackLoader(t *testing.T) {
	t.Run("requires TUF client", func(t *testing.T) {
		_, err := NewPackLoader(PackLoaderConfig{})
		if err == nil {
			t.Error("expected error for missing TUF client")
		}
	})

	t.Run("creates loader with TUF client", func(t *testing.T) {
		tufClient := &TUFClient{}
		loader, err := NewPackLoader(PackLoaderConfig{
			TUFClient: tufClient,
		})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if loader == nil {
			t.Error("expected non-nil loader")
		}
	})
}

func TestPackLoadError(t *testing.T) {
	err := &PackLoadError{
		Step:       "TUF verification",
		Reason:     "metadata expired",
		FailClosed: true,
	}

	expectedMsg := "pack load failed at step 'TUF verification': metadata expired (fail_closed=true)"
	if err.Error() != expectedMsg {
		t.Errorf("wrong error message: %s", err.Error())
	}
}

func TestValidatePackName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"org.example/my-pack", false},
		{"helm.mindburn.run/core-pack", false},
		{"a/b", false},
		{"invalid", true},        // No org separator
		{"Org/pack", true},       // Uppercase
		{"org/", true},           // Empty pack name
		{"/pack", true},          // Empty org
		{"org/pack/extra", true}, // Too many slashes
		{"org_bad/pack", true},   // Underscore in org
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePackName(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePackName(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePackHash(t *testing.T) {
	tests := []struct {
		hash    string
		wantErr bool
	}{
		{"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false}, // Valid SHA256
		{"sha256:abc123", true},    // Too short
		{"md5:abc123def456", true}, // Wrong algorithm
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true}, // Missing prefix
		{"sha256:XYZ123", true}, // Invalid hex chars
	}

	for _, tt := range tests {
		t.Run(tt.hash, func(t *testing.T) {
			err := ValidatePackHash(tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePackHash(%q) error = %v, wantErr %v", tt.hash, err, tt.wantErr)
			}
		})
	}
}

// MockVersionStore for testing
type mockVersionStore struct {
	versions map[string]*semver.Version
	err      error
}

func (m *mockVersionStore) GetInstalledVersion(packID string) (*semver.Version, error) {
	if m.err != nil {
		return nil, m.err
	}
	if v, ok := m.versions[packID]; ok {
		return v, nil
	}
	return nil, nil
}

func (m *mockVersionStore) SetInstalledVersion(packID string, version *semver.Version) error {
	if m.versions == nil {
		m.versions = make(map[string]*semver.Version)
	}
	m.versions[packID] = version
	return nil
}

// MockKeyStatusStore for testing
type mockKeyStatusStore struct {
	statuses       map[string]KeyStatus
	overrides      map[string]*QuarantineOverride
	statusErrors   map[string]error
	overrideErrors map[string]error
}

func (m *mockKeyStatusStore) GetKeyStatus(keyID string) (KeyStatus, error) {
	if err, ok := m.statusErrors[keyID]; ok {
		return "", err
	}
	if s, ok := m.statuses[keyID]; ok {
		return s, nil
	}
	return KeyStatusActive, nil
}

func (m *mockKeyStatusStore) GetQuarantineOverride(keyID string) (*QuarantineOverride, error) {
	if err, ok := m.overrideErrors[keyID]; ok {
		return nil, err
	}
	if o, ok := m.overrides[keyID]; ok {
		return o, nil
	}
	return nil, nil
}

func TestPackLoaderValidatePackLoad(t *testing.T) {
	const (
		packName = "org.example/my-pack"
		packHash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	)

	t.Run("passes complete trust chain for community pack", func(t *testing.T) {
		loader := &PackLoader{
			tufClient:      newPackLoaderTUFClient(t, packName, packHash, nil),
			versionStore:   &mockVersionStore{},
			keyStatusStore: &mockKeyStatusStore{statuses: map[string]KeyStatus{"publisher": KeyStatusActive}},
		}

		err := loader.ValidatePackLoad(PackRef{
			Name:           packName,
			Version:        "1.0.0",
			Hash:           packHash,
			PublisherKeyID: "publisher",
		})
		if err != nil {
			t.Fatalf("ValidatePackLoad: %v", err)
		}
	})

	t.Run("fails closed when TUF update fails", func(t *testing.T) {
		client := newPackLoaderTUFClient(t, packName, packHash, nil)
		client.remoteURL = "http://127.0.0.1:1"
		err := (&PackLoader{tufClient: client}).ValidatePackLoad(PackRef{Name: packName, Version: "1.0.0", Hash: packHash})
		assertPackLoadStep(t, err, "TUF metadata update", true)
	})

	t.Run("fails closed when target is missing", func(t *testing.T) {
		loader := &PackLoader{tufClient: newPackLoaderTUFClient(t, packName, packHash, nil)}
		err := loader.ValidatePackLoad(PackRef{Name: "org.example/missing", Version: "1.0.0", Hash: packHash})
		assertPackLoadStep(t, err, "TUF target lookup", true)
	})

	t.Run("fails closed when target hash mismatches", func(t *testing.T) {
		loader := &PackLoader{tufClient: newPackLoaderTUFClient(t, packName, packHash, nil)}
		err := loader.ValidatePackLoad(PackRef{Name: packName, Version: "1.0.0", Hash: "sha256:wrong"})
		assertPackLoadStep(t, err, "Hash verification", true)
	})

	t.Run("requires certified delegation for certified packs", func(t *testing.T) {
		loader := &PackLoader{tufClient: newPackLoaderTUFClient(t, packName, packHash, nil)}
		err := loader.ValidatePackLoad(PackRef{Name: packName, Version: "1.0.0", Hash: packHash, Certified: true})
		assertPackLoadStep(t, err, "Certified delegation verification", true)
	})

	t.Run("accepts certified pack with matching delegation", func(t *testing.T) {
		delegations := &Delegations{
			Roles: []DelegatedRole{{
				Name:      "certified",
				Threshold: 1,
				Paths:     []string{packName},
			}},
		}
		loader := &PackLoader{tufClient: newPackLoaderTUFClient(t, packName, packHash, delegations)}
		err := loader.ValidatePackLoad(PackRef{Name: packName, Version: "1.0.0", Hash: packHash, Certified: true})
		if err != nil {
			t.Fatalf("ValidatePackLoad certified: %v", err)
		}
	})

	t.Run("transparency log failure is non-fail-closed for community pack", func(t *testing.T) {
		rekorServer := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(rekorServer.Close)
		rekor, err := NewRekorClient(RekorClientConfig{LogURL: rekorServer.URL})
		if err != nil {
			t.Fatalf("NewRekorClient: %v", err)
		}

		loader := &PackLoader{
			tufClient:   newPackLoaderTUFClient(t, packName, packHash, nil),
			rekorClient: rekor,
		}
		err = loader.ValidatePackLoad(PackRef{Name: packName, Version: "1.0.0", Hash: packHash})
		assertPackLoadStep(t, err, "Transparency log verification", false)
	})

	t.Run("rejects invalid and rollback versions", func(t *testing.T) {
		loader := &PackLoader{
			tufClient:    newPackLoaderTUFClient(t, packName, packHash, nil),
			versionStore: &mockVersionStore{},
		}
		err := loader.ValidatePackLoad(PackRef{Name: packName, Version: "not-semver", Hash: packHash})
		assertPackLoadStep(t, err, "Monotonic versioning check", true)

		current, semverErr := semver.NewVersion("2.0.0")
		if semverErr != nil {
			t.Fatal(semverErr)
		}
		loader = &PackLoader{
			tufClient:    newPackLoaderTUFClient(t, packName, packHash, nil),
			versionStore: &mockVersionStore{versions: map[string]*semver.Version{packName: current}},
		}
		err = loader.ValidatePackLoad(PackRef{Name: packName, Version: "1.0.0", Hash: packHash})
		assertPackLoadStep(t, err, "Monotonic versioning check", true)
	})

	t.Run("publisher key status failure uses certification fail-closed setting", func(t *testing.T) {
		loader := &PackLoader{
			tufClient:      newPackLoaderTUFClient(t, packName, packHash, nil),
			keyStatusStore: &mockKeyStatusStore{statuses: map[string]KeyStatus{"publisher": KeyStatusRevoked}},
		}
		err := loader.ValidatePackLoad(PackRef{Name: packName, Version: "1.0.0", Hash: packHash, PublisherKeyID: "publisher"})
		assertPackLoadStep(t, err, "Publisher key status check", false)
	})
}

func TestPackLoader_enforceMonotonicVersion(t *testing.T) {
	currentVersion, _ := semver.NewVersion("1.0.0")
	versionStore := &mockVersionStore{
		versions: map[string]*semver.Version{
			"org.example/my-pack": currentVersion,
		},
	}

	loader := &PackLoader{
		tufClient:    &TUFClient{},
		versionStore: versionStore,
	}

	t.Run("allows upgrade", func(t *testing.T) {
		packRef := PackRef{
			Name:    "org.example/my-pack",
			Version: "2.0.0",
		}
		err := loader.enforceMonotonicVersion(packRef)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("denies downgrade", func(t *testing.T) {
		packRef := PackRef{
			Name:    "org.example/my-pack",
			Version: "0.5.0",
		}
		err := loader.enforceMonotonicVersion(packRef)
		if err == nil {
			t.Error("expected error for version rollback")
		}
	})

	t.Run("allows same version", func(t *testing.T) {
		packRef := PackRef{
			Name:    "org.example/my-pack",
			Version: "1.0.0",
		}
		err := loader.enforceMonotonicVersion(packRef)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("allows new pack", func(t *testing.T) {
		packRef := PackRef{
			Name:    "org.example/new-pack",
			Version: "1.0.0",
		}
		err := loader.enforceMonotonicVersion(packRef)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("allows install when version store errors", func(t *testing.T) {
		loader := &PackLoader{versionStore: &mockVersionStore{err: errors.New("store unavailable")}}
		err := loader.enforceMonotonicVersion(PackRef{Name: "org.example/my-pack", Version: "1.0.0"})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestPackLoader_checkPublisherStatus(t *testing.T) {
	keyStore := &mockKeyStatusStore{
		statuses: map[string]KeyStatus{
			"active-key":  KeyStatusActive,
			"revoked-key": KeyStatusRevoked,
			"expired-key": KeyStatusExpired,
		},
		overrides: map[string]*QuarantineOverride{
			"revoked-with-override": {
				PublisherKeyID: "revoked-with-override",
				Reason:         "incident response validation",
				AuthorizedBy:   []string{"security-lead"},
				ExpiresAt:      time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				Signatures:     []string{"sig1"},
			},
		},
	}
	keyStore.statuses["revoked-with-override"] = KeyStatusRevoked

	loader := &PackLoader{
		tufClient:      &TUFClient{},
		keyStatusStore: keyStore,
	}

	t.Run("allows active key", func(t *testing.T) {
		err := loader.checkPublisherStatus("active-key")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("rejects revoked key", func(t *testing.T) {
		err := loader.checkPublisherStatus("revoked-key")
		if err == nil {
			t.Error("expected error for revoked key")
		}
	})

	t.Run("rejects expired key", func(t *testing.T) {
		err := loader.checkPublisherStatus("expired-key")
		if err == nil {
			t.Error("expected error for expired key")
		}
	})

	t.Run("allows revoked key with valid override", func(t *testing.T) {
		err := loader.checkPublisherStatus("revoked-with-override")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("reports key status lookup errors", func(t *testing.T) {
		loader := &PackLoader{
			keyStatusStore: &mockKeyStatusStore{
				statusErrors: map[string]error{"error-key": errors.New("status lookup failed")},
			},
		}
		err := loader.checkPublisherStatus("error-key")
		if err == nil {
			t.Fatal("expected key status lookup error")
		}
	})

	t.Run("rejects revoked key when override lookup fails", func(t *testing.T) {
		loader := &PackLoader{
			keyStatusStore: &mockKeyStatusStore{
				statuses:       map[string]KeyStatus{"revoked-error": KeyStatusRevoked},
				overrideErrors: map[string]error{"revoked-error": errors.New("override lookup failed")},
			},
		}
		err := loader.checkPublisherStatus("revoked-error")
		if err == nil {
			t.Fatal("expected revoked key with override lookup error to fail")
		}
	})
}

func TestQuarantineOverride_IsValid(t *testing.T) {
	t.Run("invalid when nil", func(t *testing.T) {
		var o *QuarantineOverride
		if o.IsValid() {
			t.Error("nil override should be invalid")
		}
	})

	t.Run("invalid without signatures", func(t *testing.T) {
		o := &QuarantineOverride{
			PublisherKeyID: "key1",
			Signatures:     []string{},
		}
		if o.IsValid() {
			t.Error("override without signatures should be invalid")
		}
	})

	t.Run("valid with signatures", func(t *testing.T) {
		o := &QuarantineOverride{
			PublisherKeyID: "key1",
			Reason:         "incident response validation",
			AuthorizedBy:   []string{"security-lead"},
			ExpiresAt:      time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			Signatures:     []string{"sig1", "sig2"},
		}
		if !o.IsValid() {
			t.Error("override with signatures should be valid")
		}
	})

	t.Run("invalid when expiry cannot be parsed", func(t *testing.T) {
		o := &QuarantineOverride{
			PublisherKeyID: "key1",
			Reason:         "incident response validation",
			AuthorizedBy:   []string{"security-lead"},
			ExpiresAt:      "not-a-time",
			Signatures:     []string{"sig1"},
		}
		if o.IsValid() {
			t.Error("override with malformed expiry should be invalid")
		}
	})
}

func newPackLoaderTUFClient(t *testing.T, packName, packHash string, delegations *Delegations) *TUFClient {
	t.Helper()

	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".json")
		var signed json.RawMessage
		switch role {
		case string(TUFRoleTimestamp), string(TUFRoleSnapshot):
			signed = mustMarshal(RoleMetadata{
				Type:    role,
				Version: 1,
				Expires: time.Now().UTC().Add(time.Hour),
			})
		case string(TUFRoleTargets):
			signed = mustMarshal(TargetsMetadata{
				RoleMetadata: RoleMetadata{
					Type:    role,
					Version: 1,
					Expires: time.Now().UTC().Add(time.Hour),
				},
				Targets: map[string]TargetInfo{
					packName: {
						Length: int64(len(packHash)),
						Hashes: map[string]string{"sha256": packHash},
					},
				},
				Delegations: delegations,
			})
		default:
			http.NotFound(w, r)
			return
		}
		err := json.NewEncoder(w).Encode(SignedRole{
			Signed:     signed,
			Signatures: []TUFSignature{{KeyID: "root", Signature: signPackLoaderTUFRole(signed, priv)}},
		})
		if err != nil {
			t.Errorf("Encode %s metadata: %v", role, err)
		}
	}))
	t.Cleanup(server.Close)

	pub := priv.Public()
	client, err := NewTUFClient(TUFClientConfig{
		RemoteURL: server.URL,
		RootKeys:  []crypto.PublicKey{pub},
	})
	if err != nil {
		t.Fatalf("NewTUFClient: %v", err)
	}
	return client
}

func signPackLoaderTUFRole(signed json.RawMessage, priv ed25519.PrivateKey) string {
	hash := sha256.Sum256(signed)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, hash[:]))
}

func assertPackLoadStep(t *testing.T, err error, step string, failClosed bool) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected PackLoadError for %s", step)
	}
	loadErr, ok := err.(*PackLoadError)
	if !ok {
		t.Fatalf("error = %T %[1]v, want *PackLoadError", err)
	}
	if loadErr.Step != step || loadErr.FailClosed != failClosed {
		t.Fatalf("load error = %+v, want step=%q failClosed=%v", loadErr, step, failClosed)
	}
}
