package trust

import (
	"testing"

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
}

func (m *mockVersionStore) GetInstalledVersion(packID string) (*semver.Version, error) {
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
	statuses  map[string]KeyStatus
	overrides map[string]*QuarantineOverride
}

func (m *mockKeyStatusStore) GetKeyStatus(keyID string) (KeyStatus, error) {
	if s, ok := m.statuses[keyID]; ok {
		return s, nil
	}
	return KeyStatusActive, nil
}

func (m *mockKeyStatusStore) GetQuarantineOverride(keyID string) (*QuarantineOverride, error) {
	if o, ok := m.overrides[keyID]; ok {
		return o, nil
	}
	return nil, nil
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
			Signatures:     []string{"sig1", "sig2"},
		}
		if !o.IsValid() {
			t.Error("override with signatures should be valid")
		}
	})
}
