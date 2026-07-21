// quantum_posture: exercises classical Ed25519 seal/verify paths only.
package updatebundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func testSigner(t *testing.T) *crypto.Ed25519Signer {
	t.Helper()
	seed := bytes.Repeat([]byte{9}, ed25519.SeedSize)
	return crypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(seed), "bundle-test-key")
}

func fixturePayloads() map[string][]byte {
	return map[string][]byte{
		"policy_packs/soc2_type2.v1.json": []byte(`{"pack":"soc2_type2","version":1}` + "\n"),
		"notes/README.txt":                []byte("offline update bundle fixture\n"),
	}
}

func entriesFor(payloads map[string][]byte) []BundleEntry {
	paths := make([]string, 0, len(payloads))
	for path := range payloads {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	entries := make([]BundleEntry, 0, len(paths))
	for _, path := range paths {
		sum := sha256.Sum256(payloads[path])
		entries = append(entries, BundleEntry{
			Path:   path,
			SHA256: "sha256:" + hex.EncodeToString(sum[:]),
			Size:   int64(len(payloads[path])),
		})
	}
	return entries
}

func sealedManifest(t *testing.T, payloads map[string][]byte) UpdateBundleManifest {
	t.Helper()
	entries := entriesFor(payloads)
	setHash, err := EntrySetHash(entries)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealManifest(UpdateBundleManifest{
		SchemaVersion:   UpdateBundleManifestSchemaVersion,
		BundleID:        "bundle-2026-07",
		KernelVersion:   "0.7.4-test",
		CreatedAt:       "2026-07-21T00:00:00Z",
		Entries:         entries,
		ArtifactSetHash: setHash,
		SignerKeyID:     "bundle-test-key",
	}, testSigner(t))
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

type tarMember struct {
	name     string
	body     []byte
	typeflag byte
	linkname string
}

func buildTarGz(t *testing.T, members []tarMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, member := range members {
		header := &tar.Header{Name: member.name, Mode: 0o644, Size: int64(len(member.body)), Typeflag: member.typeflag, Linkname: member.linkname}
		if member.typeflag == 0 {
			header.Typeflag = tar.TypeReg
		}
		if header.Typeflag != tar.TypeReg {
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := tw.Write(member.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func membersFor(payloads map[string][]byte) []tarMember {
	paths := make([]string, 0, len(payloads))
	for path := range payloads {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	members := []tarMember{{name: "policy_packs/", typeflag: tar.TypeDir}}
	for _, path := range paths {
		members = append(members, tarMember{name: path, body: payloads[path]})
	}
	return members
}

func TestVerifyBundleRoundTrip(t *testing.T) {
	payloads := fixturePayloads()
	manifest := sealedManifest(t, payloads)
	bundle := buildTarGz(t, membersFor(payloads))
	if err := VerifyBundle(bytes.NewReader(bundle), manifest, testSigner(t).PublicKeyBytes()); err != nil {
		t.Fatalf("bundle must verify: %v", err)
	}
	if err := VerifyManifest(manifest, testSigner(t).PublicKeyBytes()); err != nil {
		t.Fatalf("manifest must verify standalone: %v", err)
	}
}

func TestVerifyBundleTampers(t *testing.T) {
	payloads := fixturePayloads()
	cases := []struct {
		name    string
		mutate  func(map[string][]byte, *UpdateBundleManifest, *[]tarMember)
		wantSub string
	}{
		{"content flip", func(p map[string][]byte, _ *UpdateBundleManifest, members *[]tarMember) {
			for i := range *members {
				if (*members)[i].name == "notes/README.txt" {
					// Same length as the original so the hash check (not the
					// size check) is what fires.
					(*members)[i].body = []byte("OFFLINE UPDATE BUNDLE FIXTURE\n")
				}
			}
		}, "hash"},
		{"size lie shorter member", func(p map[string][]byte, _ *UpdateBundleManifest, members *[]tarMember) {
			for i := range *members {
				if (*members)[i].name == "notes/README.txt" {
					(*members)[i].body = []byte("short\n")
				}
			}
		}, "size"},
		{"extra member", func(_ map[string][]byte, _ *UpdateBundleManifest, members *[]tarMember) {
			*members = append(*members, tarMember{name: "extra/implant.bin", body: []byte("x")})
		}, "not in the signed manifest"},
		{"missing member", func(_ map[string][]byte, _ *UpdateBundleManifest, members *[]tarMember) {
			kept := (*members)[:0]
			for _, member := range *members {
				if member.name != "notes/README.txt" {
					kept = append(kept, member)
				}
			}
			*members = kept
		}, "missing manifest entry"},
		{"path traversal member", func(_ map[string][]byte, _ *UpdateBundleManifest, members *[]tarMember) {
			*members = append(*members, tarMember{name: "../etc/evil", body: []byte("x")})
		}, "clean"},
		{"symlink member", func(_ map[string][]byte, _ *UpdateBundleManifest, members *[]tarMember) {
			*members = append(*members, tarMember{name: "notes/link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"})
		}, "unsupported type"},
		{"duplicate member", func(p map[string][]byte, _ *UpdateBundleManifest, members *[]tarMember) {
			*members = append(*members, tarMember{name: "notes/README.txt", body: p["notes/README.txt"]})
		}, "more than once"},
		{"manifest signature tamper", func(_ map[string][]byte, manifest *UpdateBundleManifest, _ *[]tarMember) {
			manifest.Signature = "ed25519:" + strings.Repeat("ab", 64)
		}, "signature"},
		{"manifest entry hash flip", func(_ map[string][]byte, manifest *UpdateBundleManifest, _ *[]tarMember) {
			manifest.Entries[0].SHA256 = "sha256:" + strings.Repeat("cd", 32)
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := fixturePayloads()
			manifest := sealedManifest(t, payloads)
			members := membersFor(p)
			tc.mutate(p, &manifest, &members)
			bundle := buildTarGz(t, members)
			err := VerifyBundle(bytes.NewReader(bundle), manifest, testSigner(t).PublicKeyBytes())
			if err == nil {
				t.Fatal("tampered bundle must not verify")
			}
			if tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestVerifyBundleWrongKey(t *testing.T) {
	payloads := fixturePayloads()
	manifest := sealedManifest(t, payloads)
	bundle := buildTarGz(t, membersFor(payloads))
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	if err := VerifyBundle(bytes.NewReader(bundle), manifest, wrong.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("verification under the wrong key must fail")
	}
}

func TestManifestShapeRejections(t *testing.T) {
	payloads := fixturePayloads()
	entries := entriesFor(payloads)
	setHash, err := EntrySetHash(entries)
	if err != nil {
		t.Fatal(err)
	}
	base := UpdateBundleManifest{
		SchemaVersion:   UpdateBundleManifestSchemaVersion,
		BundleID:        "bundle-2026-07",
		KernelVersion:   "0.7.4-test",
		CreatedAt:       "2026-07-21T00:00:00Z",
		Entries:         entries,
		ArtifactSetHash: setHash,
		SignerKeyID:     "bundle-test-key",
	}
	cases := []struct {
		name   string
		mutate func(*UpdateBundleManifest)
	}{
		{"wrong schema", func(m *UpdateBundleManifest) { m.SchemaVersion = "v2" }},
		{"bad bundle id", func(m *UpdateBundleManifest) { m.BundleID = "UPPER" }},
		{"bad created_at", func(m *UpdateBundleManifest) { m.CreatedAt = "yesterday" }},
		{"no entries", func(m *UpdateBundleManifest) { m.Entries = nil }},
		{"unsorted entries", func(m *UpdateBundleManifest) {
			m.Entries = []BundleEntry{m.Entries[1], m.Entries[0]}
		}},
		{"set hash mismatch", func(m *UpdateBundleManifest) {
			m.ArtifactSetHash = "sha256:" + strings.Repeat("ef", 32)
		}},
		{"negative size", func(m *UpdateBundleManifest) {
			m.Entries = append([]BundleEntry(nil), m.Entries...)
			m.Entries[0].Size = -1
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := base
			tc.mutate(&manifest)
			if _, err := SealManifest(manifest, testSigner(t)); err == nil {
				t.Fatal("invalid manifest must not seal")
			}
		})
	}
}
