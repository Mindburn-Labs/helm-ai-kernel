package skillpacks

// quantum_posture: first-party packs are pinned by SHA-256 content digests
// compiled into the binary. Nothing here verifies a signature; a release
// binary's own keyless cosign bundle is checked outside this package. No
// post-quantum claim.

import (
	_ "embed"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/profile/updatebundle"
)

// first_party_manifest.json pins the packs under registry/skills/helm, and the
// kernel skill policy, as they were in the tree this binary was built from. It
// is the only trust material this package has for "first party". A pack cannot
// supply it or point at another one, and the binary is as trustworthy as the
// release it came from. TestFirstPartyManifestMatchesTheRegistry regenerates
// it and fails when the registry and the pins differ.
//
//go:embed first_party_manifest.json
var embeddedFirstPartyManifest []byte

const firstPartyManifestSchemaV1 = "helm.skillpack.first-party-manifest.v1"

type firstPartyManifest struct {
	SchemaVersion string           `json:"schema_version"`
	Policy        kernelPolicyPin  `json:"policy"`
	Packs         []firstPartyPack `json:"packs"`
}

// kernelPolicyPin identifies the written statement of the scan rules. The
// rules themselves are code in this package; no policy file is read at scan
// time.
type kernelPolicyPin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// firstPartyPack pins one pack. ContentDigest is the artifact set hash of
// Files, the same derivation update bundles use, so a pack and its pin are
// compared over every file and not over SKILL.md alone.
type firstPartyPack struct {
	ID            string                     `json:"id"`
	Version       string                     `json:"version"`
	ContentDigest string                     `json:"content_digest"`
	Files         []updatebundle.BundleEntry `json:"files"`
}

// firstPartyTrust is the trust material a scan judges the publisher against.
// It never comes from a pack: Scan and Install pass the manifest compiled into
// the binary. A nil *firstPartyTrust means the caller verifies the publisher
// itself, as ProjectionLifecycle does through its configured verifier.
type firstPartyTrust struct {
	manifest firstPartyManifest
	// err is why the manifest cannot be used. No pack is first party then.
	err error
}

var loadKernelFirstPartyTrust = sync.OnceValue(func() *firstPartyTrust {
	manifest, err := parseFirstPartyManifest(embeddedFirstPartyManifest)
	return &firstPartyTrust{manifest: manifest, err: err}
})

func parseFirstPartyManifest(data []byte) (firstPartyManifest, error) {
	var manifest firstPartyManifest
	if err := decodeStrictProjectionJSON(data, &manifest); err != nil {
		return firstPartyManifest{}, fmt.Errorf("parse first-party manifest: %w", err)
	}
	if manifest.SchemaVersion != firstPartyManifestSchemaV1 {
		return firstPartyManifest{}, fmt.Errorf("unsupported first-party manifest schema %q", manifest.SchemaVersion)
	}
	if strings.TrimSpace(manifest.Policy.Path) == "" || !validProjectionSHA256(manifest.Policy.SHA256) {
		return firstPartyManifest{}, errors.New("first-party manifest does not pin the kernel skill policy")
	}
	seen := map[string]bool{}
	for _, pack := range manifest.Packs {
		if !skillIDPattern.MatchString(pack.ID) || strings.TrimSpace(pack.Version) == "" || seen[pack.ID] {
			return firstPartyManifest{}, fmt.Errorf("first-party manifest pins %q@%q more than once or with an invalid identity", pack.ID, pack.Version)
		}
		seen[pack.ID] = true
		// A pin whose digest does not follow from its own file list would
		// make every mismatch report name the wrong files.
		digest, err := updatebundle.EntrySetHash(pack.Files)
		if err != nil || digest != pack.ContentDigest {
			return firstPartyManifest{}, fmt.Errorf("first-party manifest pin for %s is inconsistent", pack.ID)
		}
	}
	return manifest, nil
}

// pin returns the entry for id, at whatever version the binary pins it.
func (m firstPartyManifest) pin(id string) (firstPartyPack, bool) {
	for _, pack := range m.Packs {
		if pack.ID == id {
			return pack, true
		}
	}
	return firstPartyPack{}, false
}

// scanPolicy names the rules a scan runs under. The hash is the pinned policy
// file's, so it is empty when the manifest is unusable; no pack is ALLOW then,
// and no receipt is written with it.
func (t *firstPartyTrust) scanPolicy() ScanPolicy {
	return ScanPolicy{Source: PolicySourceKernel, Ref: t.manifest.Policy.Path, Hash: t.manifest.Policy.SHA256}
}

// CheckPublisher reports what this binary can establish about who published
// pack. It reads the pack's files once and compares them with the first-party
// manifest compiled into the binary; it checks no signature.
func CheckPublisher(pack SkillPack) PublisherVerification {
	if pack.Root == "" {
		return checkPublisher(pack, nil, loadKernelFirstPartyTrust())
	}
	tree, err := readPackTree(pack.Root)
	if err != nil {
		tree = packTree{unhashed: err.Error()}
	}
	return checkPublisher(pack, &tree, loadKernelFirstPartyTrust())
}

// checkPublisher decides the publisher state from the files that were read
// (tree, nil when the pack has no directory) and the trust material. Nothing
// the manifest says about publisher, status, signature or key is consulted:
// the id and version only select which pin the files are compared with.
func checkPublisher(pack SkillPack, tree *packTree, trust *firstPartyTrust) PublisherVerification {
	if trust == nil {
		return PublisherVerification{
			State: PublisherNotChecked, Basis: PublisherBasisProjectionVerifier,
			Reason: "the publisher is not judged by this scan: the projection lifecycle binds trust to its configured verifier's signed decision",
		}
	}
	id, version := pack.Manifest.ID, pack.Manifest.Version
	result := PublisherVerification{State: PublisherUnsigned, Basis: PublisherBasisNone}
	var digestErr error
	switch {
	case tree == nil:
		digestErr = errors.New("the pack was not loaded from a directory, so there are no files to hash")
	default:
		result.ContentDigest, digestErr = tree.contentDigest()
		if digestErr == nil {
			digestErr = tree.holds(pack)
		}
	}
	if trust.err != nil {
		result.Reason = fmt.Sprintf("no pack can be checked: the first-party manifest of this binary is unusable (%v)", trust.err)
		return result
	}
	pin, pinned := trust.manifest.pin(id)
	if !pinned || pin.Version != version {
		result.Reason = fmt.Sprintf("no publisher was verified: %s@%s is not in the first-party manifest this binary was built with", id, version)
		if pinned {
			result.Reason += fmt.Sprintf(" (it pins %s only at version %s)", id, pin.Version)
		}
		result.Reason += ", and HELM has no publisher signature format or publisher key for SkillPacks, so signature_ref and publisher_key_ref are labels that nothing checks"
		return result
	}
	result.Basis = PublisherBasisFirstPartyManifest
	if digestErr != nil {
		result.State = PublisherFirstPartyMismatch
		result.Reason = fmt.Sprintf("this binary pins %s@%s, but the pack's files could not be compared with the pin: %v", id, version, digestErr)
		return result
	}
	if result.ContentDigest != pin.ContentDigest {
		result.State = PublisherFirstPartyMismatch
		result.Reason = fmt.Sprintf("this binary pins %s@%s at %s; the pack's files hash to %s (%s)",
			id, version, pin.ContentDigest, result.ContentDigest, describeEntryDifference(pin.Files, tree.entries()))
		return result
	}
	result.State = PublisherFirstParty
	result.Reason = fmt.Sprintf("every file of the pack hashes to the digest this binary was built with for %s@%s; no signature was checked", id, version)
	return result
}

// describeEntryDifference names the files that make a pack differ from its
// pin, so an operator can see what changed without diffing by hand.
func describeEntryDifference(pinned, found []updatebundle.BundleEntry) string {
	want := map[string]string{}
	for _, entry := range pinned {
		want[entry.Path] = entry.SHA256
	}
	var parts []string
	for _, entry := range found {
		hash, known := want[entry.Path]
		switch {
		case !known:
			parts = append(parts, entry.Path+" is not part of the pinned pack")
		case hash != entry.SHA256:
			parts = append(parts, entry.Path+" differs")
		}
		delete(want, entry.Path)
	}
	missing := make([]string, 0, len(want))
	for path := range want {
		missing = append(missing, path)
	}
	sort.Strings(missing)
	for _, path := range missing {
		parts = append(parts, path+" is missing")
	}
	const maxNamed = 8
	if len(parts) > maxNamed {
		parts = append(parts[:maxNamed], fmt.Sprintf("and %d more", len(parts)-maxNamed))
	}
	return strings.Join(parts, "; ")
}
