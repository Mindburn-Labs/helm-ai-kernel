package siwc

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestHostIdentityIsStableCanonicalUUIDv4URN(t *testing.T) {
	s := newStore(t)
	id, err := uuid.Parse(s.hostID)
	if err != nil || id.Version() != 4 || id.Variant() != uuid.RFC4122 || s.hostID != id.URN() {
		t.Fatal("new host is not the supported canonical UUIDv4 URN")
	}
	before, err := os.ReadFile(filepath.Join(s.dir, "host.json"))
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(s.dir)
	if err != nil || reopened.hostID != s.hostID {
		t.Fatal("host changed across restart", err)
	}
	after, err := os.ReadFile(filepath.Join(s.dir, "host.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("restart rewrote the persisted identity", err)
	}
	if newStore(t).hostID == s.hostID {
		t.Fatal("independent hosts reused an identity")
	}
	f := newOIDC(t)
	a, err := f.login(reopened, "", nil)
	if err != nil || a.HostID != s.hostID || f.request.Get("ext_agent_host_id") != s.hostID {
		t.Fatal("authorization registration lost the stable host identity", err)
	}
}

func TestUnsupportedHostDoesNotRewriteRegistrationOrCredentials(t *testing.T) {
	for name, host := range map[string]string{
		"legacy-base64": strings.Repeat("a", 43),
		"bare-uuid":     "b3dd053b-0508-4f8d-8f9a-060d6db4df67",
		"uppercase":     "urn:uuid:B3DD053B-0508-4F8D-8F9A-060D6DB4DF67",
		"wrong-version": "urn:uuid:b3dd053b-0508-1f8d-8f9a-060d6db4df67",
		"wrong-variant": "urn:uuid:b3dd053b-0508-4f8d-cf9a-060d6db4df67",
		"invalid":       "urn:uuid:broken",
	} {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			files := map[string][]byte{
				"host.json":              []byte(`{"host_id":"` + host + `"}`),
				"registration.json":      []byte(`{"client_id":"oaiapp_preserved"}`),
				"account-preserved.json": []byte(`{"refresh_token":"synthetic-preserved"}`),
			}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(s.dir, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := OpenStore(s.dir); !errors.Is(err, ErrHostIdentity) {
				t.Fatal("unsupported persisted identity was accepted", err)
			}
			for name, before := range files {
				after, err := os.ReadFile(filepath.Join(s.dir, name))
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("existing registration or credential data changed", name, err)
				}
			}
		})
	}
}
