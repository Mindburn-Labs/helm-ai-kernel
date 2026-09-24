package skillpacks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// These tests reproduce the HELM-737 audit PoCs (21-04, 21-05, 21-09). A
// repository the user cloned controls its own registry, its skill policy,
// .helm/skillpacks/installed.json and any symlink it commits. `skills install`
// and `skills revoke` run inside that checkout must not write or delete
// anything outside it, and a pack no trusted key vouches for must not install.

const testSkillPolicyRef = "policies/skills/test.safe.toml"

const testSkillPolicy = `[skill]
permission_bypass_forbidden = true
receipts_required = true
global_install_default = "deny"
mcp_auto_enable_default = "quarantine"
[projection]
[evidence]
`

// firstPartyTestManifest passes the first-party keyring check. That check
// compares strings, so a cloned repository can present the same manifest:
// install and revoke containment must hold even when the scan says ALLOW.
func firstPartyTestManifest(id, version string) Manifest {
	name := id[strings.Index(id, "/")+1:]
	return Manifest{
		SchemaVersion: "helm.skillpack.v1", ID: id, Name: name, Version: version,
		Description: "safe skill", Publisher: "Mindburn-Labs", Status: StatusVerified,
		ScopeDefault: ScopeRepo, Risk: "LOW", LicenseSPDX: "Apache-2.0",
		SignatureRef: "helm-first-party://skills/" + name + "/" + version,
		PolicyRef:    testSkillPolicyRef, PermissionsDoNotGrantTools: true,
	}
}

// attackerClone lays out the VD PoC under one parent directory: the cloned
// repository, holding the pack in its own registry plus a repository policy,
// and a victim home beside it whose files must survive.
func attackerClone(t *testing.T, manifest Manifest, skill string) (clone, victimHome string) {
	t.Helper()
	parent := t.TempDir()
	clone = filepath.Join(parent, "victim-clone")
	victimHome = filepath.Join(parent, "victim-home")
	writeSkillAt(t, filepath.Join(clone, "registry", "skills", filepath.FromSlash(manifest.ID)), manifest, skill)
	writeTestFile(t, filepath.Join(clone, filepath.FromSlash(testSkillPolicyRef)), testSkillPolicy)
	writeTestFile(t, filepath.Join(victimHome, "profile.txt"), "original profile\n")
	return clone, victimHome
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("%s = %q err=%v, want %q", path, got, err, want)
	}
}

// skillpoc2: the clone commits .agents/skills/acme/tool/SKILL.md.tmp as a
// relative symlink to a file outside the checkout, then the user runs
// `skills install acme/tool --agent codex` inside it.
func TestInstallIgnoresPlantedTempSymlink(t *testing.T) {
	clone, victimHome := attackerClone(t, firstPartyTestManifest("acme/tool", "1.0.0"), "echo pwned-by-skill-install\n")
	projectionDir := filepath.Join(clone, ".agents", "skills", "acme", "tool")
	if err := os.MkdirAll(projectionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join("..", "..", "..", "..", "..", "victim-home", "profile.txt")
	if err := os.Symlink(target, filepath.Join(projectionDir, "SKILL.md.tmp")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	t.Chdir(clone)

	pack, err := Load("acme/tool")
	if err != nil {
		t.Fatal(err)
	}
	result, err := Install(pack, InstallRequest{Agent: "codex"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictAllow || result.Status != "active" {
		t.Fatalf("the scan must pass so the write path is exercised: %+v", result)
	}
	assertFileContent(t, filepath.Join(victimHome, "profile.txt"), "original profile\n")
	info, err := os.Lstat(filepath.Join(projectionDir, "SKILL.md"))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("projection must be a regular file inside the clone: info=%v err=%v", info, err)
	}
	assertFileContent(t, filepath.Join(projectionDir, "SKILL.md"), pack.SkillMD)
}

// 21-04: a committed directory symlink on any managed path (the projection
// parent or the .helm store) must stop the install instead of redirecting it.
func TestInstallRefusesSymlinkedManagedDirectories(t *testing.T) {
	for _, tc := range []struct {
		name  string
		agent string
		link  string
	}{
		{name: "codex projection parent", agent: "codex", link: filepath.Join(".agents", "skills", "acme")},
		{name: "claude projection root", agent: "claude-code", link: filepath.Join(".claude", "skills")},
		{name: "install store and receipts", agent: "codex", link: filepath.Join(".helm", "skillpacks")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clone, victimHome := attackerClone(t, firstPartyTestManifest("acme/tool", "1.0.0"), "safe skill\n")
			outside := filepath.Join(victimHome, "planted")
			if err := os.MkdirAll(outside, 0o755); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(clone, tc.link)
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			pack, err := LoadDir(filepath.Join(clone, "registry", "skills", "acme", "tool"))
			if err != nil {
				t.Fatal(err)
			}

			if _, err := Install(pack, InstallRequest{Agent: tc.agent, RepoRoot: clone}); !errors.Is(err, ErrProjectionPathUnsafe) {
				t.Fatalf("install through %s error = %v, want ErrProjectionPathUnsafe", tc.link, err)
			}
			entries, err := os.ReadDir(outside)
			if err != nil || len(entries) != 0 {
				t.Fatalf("install wrote outside the clone: entries=%v err=%v", entries, err)
			}
		})
	}
}

// 21-09: the PoC manifest is experimental with signature_ref "sig". No key
// checks that reference, so the pack is unsigned and must not install.
func TestInstallBlocksUnsignedPack(t *testing.T) {
	manifest := Manifest{
		SchemaVersion: "helm.skillpack.v1", ID: "acme/tool", Name: "tool", Version: "1.0.0",
		Description: "formatter", Publisher: "acme", Status: StatusExperimental,
		ScopeDefault: ScopeRepo, Risk: "LOW", LicenseSPDX: "MIT", SignatureRef: "sig",
		PolicyRef: testSkillPolicyRef, AgentTargets: []string{"codex"}, PermissionsDoNotGrantTools: true,
	}
	clone, _ := attackerClone(t, manifest, "formatter instructions\n")
	pack, err := LoadDir(filepath.Join(clone, "registry", "skills", "acme", "tool"))
	if err != nil {
		t.Fatal(err)
	}

	result, err := Install(pack, InstallRequest{Agent: "codex", RepoRoot: clone})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "blocked" || result.Verdict != VerdictEscalate || result.ReasonCode != "ERR_SKILL_SIGNATURE_UNVERIFIED" {
		t.Fatalf("unsigned pack install = %+v, want blocked ESCALATE", result)
	}
	for _, managed := range []string{".agents", ".helm"} {
		if _, err := os.Lstat(filepath.Join(clone, managed)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("blocked install created %s: %v", managed, err)
		}
	}
}

// 21-09: a github: pack is extracted into a temp directory with no repository
// above it. The policy check must escalate instead of being skipped.
func TestScanEscalatesRemotePackWithoutPolicyRoot(t *testing.T) {
	archive := testGitHubTarball(t, map[string]string{
		"repo-root/skills/example/skillpack.json": mustJSON(t, firstPartyTestManifest("acme/remote", "1.0.0")),
		"repo-root/skills/example/SKILL.md":       "remote skill",
	})
	root, err := extractGitHubSkillArchive(archive, "skills/example")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if _, err := findRepoRoot(root); err == nil {
		t.Skip("the temp directory has a HELM repository above it")
	}
	pack, err := LoadDir(root)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Scan(pack)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictEscalate || result.ReasonCode != "ERR_SKILL_POLICY_INVALID" {
		t.Fatalf("remote pack scan = %+v, want policy ESCALATE", result)
	}
}

// skillpoc3 and 21-05: installed.json ships inside the clone, so every path it
// lists is attacker-chosen. Revoke must remove only the canonical projection
// under the repository root, and only while it holds the recorded bytes.
func TestRevokeRemovesOnlyRecordedProjectionInsideRoot(t *testing.T) {
	for _, tc := range []struct {
		name    string
		seed    func(t *testing.T, clone, victimHome string) (Projection, string, string)
		wantErr error
	}{
		{
			name: "relative path out of the clone",
			seed: func(t *testing.T, _, victimHome string) (Projection, string, string) {
				keyfile := filepath.Join(victimHome, "keyfile.txt")
				writeTestFile(t, keyfile, "secret key\n")
				return Projection{Agent: "codex", Path: filepath.Join("..", "victim-home", "keyfile.txt")}, HashBytes([]byte("secret key\n")), keyfile
			},
			wantErr: ErrProjectionPathUnsafe,
		},
		{
			name: "absolute path out of the clone",
			seed: func(t *testing.T, _, victimHome string) (Projection, string, string) {
				keyfile := filepath.Join(victimHome, "keyfile.txt")
				writeTestFile(t, keyfile, "secret key\n")
				return Projection{Agent: "codex", Path: keyfile}, HashBytes([]byte("secret key\n")), keyfile
			},
			wantErr: ErrProjectionPathUnsafe,
		},
		{
			name: "canonical path through a symlinked directory",
			seed: func(t *testing.T, clone, victimHome string) (Projection, string, string) {
				outside := filepath.Join(victimHome, "planted", "tool", "SKILL.md")
				writeTestFile(t, outside, "outside skill\n")
				link := filepath.Join(clone, ".agents", "skills", "acme")
				if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(victimHome, "planted"), link); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				return canonicalCodexProjection(t, clone), HashBytes([]byte("outside skill\n")), outside
			},
			wantErr: ErrProjectionPathUnsafe,
		},
		{
			name: "projection bytes differ from the store record",
			seed: func(t *testing.T, clone, _ string) (Projection, string, string) {
				projected := filepath.Join(clone, ".agents", "skills", "acme", "tool", "SKILL.md")
				writeTestFile(t, projected, "edited skill\n")
				return canonicalCodexProjection(t, clone), HashBytes([]byte("installed skill\n")), projected
			},
			wantErr: ErrProjectionDrift,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clone, victimHome := attackerClone(t, firstPartyTestManifest("acme/tool", "1.0.0"), "safe skill\n")
			projection, contentHash, protected := tc.seed(t, clone, victimHome)
			store := installStore{SchemaVersion: "helm.skillpack.installs.v1", Installs: []installedSkill{{
				SkillID: "acme/tool", Agent: "codex", Scope: ScopeRepo, Status: "active",
				ContentHash: contentHash, ProjectionPaths: []Projection{projection},
			}}}
			storeBytes, err := json.Marshal(store)
			if err != nil {
				t.Fatal(err)
			}
			storePath := filepath.Join(clone, ".helm", "skillpacks", "installed.json")
			writeTestFile(t, storePath, string(storeBytes))
			protectedBefore, err := os.ReadFile(protected)
			if err != nil {
				t.Fatal(err)
			}
			t.Chdir(clone)

			if _, err := Revoke("", "acme/tool"); !errors.Is(err, tc.wantErr) {
				t.Fatalf("revoke error = %v, want %v", err, tc.wantErr)
			}
			protectedAfter, err := os.ReadFile(protected)
			if err != nil || !reflect.DeepEqual(protectedAfter, protectedBefore) {
				t.Fatalf("revoke removed or changed %s: err=%v", protected, err)
			}
			assertFileContent(t, storePath, string(storeBytes))
		})
	}
}

func canonicalCodexProjection(t *testing.T, clone string) Projection {
	t.Helper()
	root, err := canonicalRepositoryRoot(clone)
	if err != nil {
		t.Fatal(err)
	}
	projections, err := ProjectionPaths(root, "acme/tool", "codex")
	if err != nil {
		t.Fatal(err)
	}
	return projections[0]
}
