package promotion

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"gopkg.in/yaml.v3"
)

const ImageLockSchemaVersion = "helm.launchpad.image-lock.v1"

type ImageLock struct {
	SchemaVersion string           `json:"schema_version"`
	GeneratedFrom []string         `json:"generated_from"`
	Images        []ImageLockEntry `json:"images"`
}

type ImageLockEntry struct {
	Name       string `json:"name"`
	Role       string `json:"role"`
	Image      string `json:"image"`
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	Source     string `json:"source"`
	Preload    bool   `json:"preload"`
}

func AppsByID(catalog *registry.Catalog, appIDs []string) ([]registry.AppSpec, error) {
	apps := make([]registry.AppSpec, 0, len(appIDs))
	seen := map[string]struct{}{}
	for _, appID := range appIDs {
		appID = strings.TrimSpace(appID)
		if appID == "" {
			continue
		}
		if _, ok := seen[appID]; ok {
			return nil, fmt.Errorf("duplicate launchpad promotion app %q", appID)
		}
		seen[appID] = struct{}{}
		app, ok := catalog.App(appID)
		if !ok {
			return nil, fmt.Errorf("app %s not found in registry", appID)
		}
		apps = append(apps, app)
	}
	if len(apps) == 0 {
		return nil, errors.New("no launchpad promotion apps selected")
	}
	return apps, nil
}

func SyncDerived(root string, apps []registry.AppSpec) error {
	if err := WriteImageLock(root, apps); err != nil {
		return err
	}
	return SyncHelmValues(root, apps)
}

func CheckDerived(root string, apps []registry.AppSpec) []string {
	var drifts []string
	for _, app := range apps {
		drifts = append(drifts, validateAppSpecRefs(app)...)
	}
	if err := CheckImageLock(root, apps); err != nil {
		drifts = append(drifts, err.Error())
	}
	if err := CheckHelmValues(root, apps); err != nil {
		drifts = append(drifts, err.Error())
	}
	if err := CheckSmokeScriptUsesImageLock(root); err != nil {
		drifts = append(drifts, err.Error())
	}
	return drifts
}

func WriteImageLock(root string, apps []registry.AppSpec) error {
	lock, err := BuildImageLock(root, apps)
	if err != nil {
		return err
	}
	data, err := MarshalImageLock(lock)
	if err != nil {
		return err
	}
	path := imageLockPath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func CheckImageLock(root string, apps []registry.AppSpec) error {
	lock, err := BuildImageLock(root, apps)
	if err != nil {
		return err
	}
	want, err := MarshalImageLock(lock)
	if err != nil {
		return err
	}
	have, err := os.ReadFile(imageLockPath(root))
	if err != nil {
		return fmt.Errorf("registry/launchpad/image-lock.json missing or unreadable: %w", err)
	}
	if !bytes.Equal(bytes.TrimSpace(have), bytes.TrimSpace(want)) {
		return fmt.Errorf("registry/launchpad/image-lock.json drift: regenerate with launch promote --sync-derived --write")
	}
	return nil
}

func BuildImageLock(root string, apps []registry.AppSpec) (ImageLock, error) {
	lock := ImageLock{
		SchemaVersion: ImageLockSchemaVersion,
		GeneratedFrom: make([]string, 0, len(apps)),
		Images:        make([]ImageLockEntry, 0, len(apps)+1),
	}
	var egress *ImageLockEntry
	for _, app := range apps {
		specPath := filepath.ToSlash(filepath.Join("registry", "launchpad", "apps", app.ID+".yaml"))
		repo, digest, err := splitImageDigest(app.Install.Image)
		if err != nil {
			return ImageLock{}, fmt.Errorf("app %s install image: %w", app.ID, err)
		}
		if digest != app.Install.Digest {
			return ImageLock{}, fmt.Errorf("app %s install image digest %s does not match install.digest %s", app.ID, digest, app.Install.Digest)
		}
		lock.GeneratedFrom = append(lock.GeneratedFrom, specPath)
		lock.Images = append(lock.Images, ImageLockEntry{
			Name:       app.ID,
			Role:       "launchpad_app",
			Image:      app.Install.Image,
			Repository: repo,
			Digest:     app.Install.Digest,
			Source:     specPath,
			Preload:    true,
		})
		if app.FrameworkContract.EgressProxy.Required {
			proxy := app.FrameworkContract.EgressProxy
			proxyRepo, proxyDigest, err := splitImageDigest(proxy.Image)
			if err != nil {
				return ImageLock{}, fmt.Errorf("app %s egress proxy image: %w", app.ID, err)
			}
			if proxyDigest != proxy.Digest {
				return ImageLock{}, fmt.Errorf("app %s egress proxy image digest %s does not match egress digest %s", app.ID, proxyDigest, proxy.Digest)
			}
			entry := ImageLockEntry{
				Name:       "egress-proxy",
				Role:       "egress_proxy",
				Image:      proxy.Image,
				Repository: proxyRepo,
				Digest:     proxy.Digest,
				Source:     specPath,
				Preload:    true,
			}
			if egress == nil {
				egress = &entry
			} else if egress.Image != entry.Image || egress.Digest != entry.Digest || egress.Repository != entry.Repository {
				return ImageLock{}, fmt.Errorf("egress proxy drift across promoted apps: %s uses %s, earlier apps use %s", app.ID, entry.Image, egress.Image)
			}
		}
	}
	if egress != nil {
		lock.Images = append(lock.Images, *egress)
	}
	return lock, nil
}

func MarshalImageLock(lock ImageLock) ([]byte, error) {
	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func SyncHelmValues(root string, apps []registry.AppSpec) error {
	path := helmValuesPath(root)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	replacements, err := helmDigestReplacements(apps)
	if err != nil {
		return err
	}
	updated, err := replaceDigestLinesAfterRepository(string(data), replacements)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(updated), 0o644)
}

func CheckHelmValues(root string, apps []registry.AppSpec) error {
	data, err := os.ReadFile(helmValuesPath(root))
	if err != nil {
		return fmt.Errorf("deploy/helm-chart/values.yaml missing or unreadable: %w", err)
	}
	type chartImage struct {
		Repository string `yaml:"repository"`
		Digest     string `yaml:"digest"`
	}
	type chartApp struct {
		Image         chartImage `yaml:"image"`
		EgressSidecar struct {
			Image chartImage `yaml:"image"`
		} `yaml:"egressSidecar"`
	}
	var values struct {
		LaunchpadApps struct {
			OpenClaw chartApp `yaml:"openclaw"`
			Hermes   chartApp `yaml:"hermes"`
		} `yaml:"launchpadApps"`
	}
	if err := yaml.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("deploy/helm-chart/values.yaml parse error: %w", err)
	}
	for _, app := range apps {
		chartApp := chartApp{}
		switch app.ID {
		case "openclaw":
			chartApp = values.LaunchpadApps.OpenClaw
		case "hermes":
			chartApp = values.LaunchpadApps.Hermes
		default:
			return fmt.Errorf("deploy/helm-chart/values.yaml has no Launchpad chart mapping for app %s", app.ID)
		}
		if chartApp.Image.Repository == "" || chartApp.Image.Digest == "" {
			return fmt.Errorf("deploy/helm-chart/values.yaml missing launchpadApps.%s", app.ID)
		}
		repo, _, err := splitImageDigest(app.Install.Image)
		if err != nil {
			return fmt.Errorf("app %s install image: %w", app.ID, err)
		}
		if chartApp.Image.Repository != repo || chartApp.Image.Digest != app.Install.Digest {
			return fmt.Errorf("helm values drift for %s image: got %s@%s want %s@%s", app.ID, chartApp.Image.Repository, chartApp.Image.Digest, repo, app.Install.Digest)
		}
		if app.FrameworkContract.EgressProxy.Required {
			proxy := app.FrameworkContract.EgressProxy
			proxyRepo, _, err := splitImageDigest(proxy.Image)
			if err != nil {
				return fmt.Errorf("app %s egress proxy image: %w", app.ID, err)
			}
			if chartApp.EgressSidecar.Image.Repository != proxyRepo || chartApp.EgressSidecar.Image.Digest != proxy.Digest {
				return fmt.Errorf("helm values drift for %s egress sidecar: got %s@%s want %s@%s", app.ID, chartApp.EgressSidecar.Image.Repository, chartApp.EgressSidecar.Image.Digest, proxyRepo, proxy.Digest)
			}
		}
	}
	return nil
}

func CheckSmokeScriptUsesImageLock(root string) error {
	data, err := os.ReadFile(filepath.Join(root, "scripts", "ci", "launchpad_k8s_smoke.sh"))
	if err != nil {
		return fmt.Errorf("scripts/ci/launchpad_k8s_smoke.sh missing or unreadable: %w", err)
	}
	text := string(data)
	var issues []string
	if !strings.Contains(text, "registry/launchpad/image-lock.json") {
		issues = append(issues, "preload images must come from registry/launchpad/image-lock.json")
	}
	hardCoded := regexp.MustCompile(`ghcr\.io/mindburn-labs/helm-launchpad/[a-z0-9-]+@sha256:[0-9a-f]{64}`)
	if hardCoded.MatchString(text) {
		issues = append(issues, "hard-coded launchpad image digest found")
	}
	if len(issues) > 0 {
		return fmt.Errorf("scripts/ci/launchpad_k8s_smoke.sh drift: %s", strings.Join(issues, "; "))
	}
	return nil
}

func validateAppSpecRefs(app registry.AppSpec) []string {
	var drifts []string
	repo, digest, err := splitImageDigest(app.Install.Image)
	if err != nil {
		drifts = append(drifts, fmt.Sprintf("app %s install image: %v", app.ID, err))
	} else if digest != app.Install.Digest {
		drifts = append(drifts, fmt.Sprintf("app %s install digest drift: image has %s, install.digest has %s", app.ID, digest, app.Install.Digest))
	}
	if app.SupplyChainEvidence.ArtifactDigest != "" && app.SupplyChainEvidence.ArtifactDigest != app.Install.Digest {
		drifts = append(drifts, fmt.Sprintf("app %s supply_chain_evidence.artifact_digest drift: got %s want %s", app.ID, app.SupplyChainEvidence.ArtifactDigest, app.Install.Digest))
	}
	if app.SupplyChainEvidence.SignatureRef != "" && !strings.Contains(app.SupplyChainEvidence.SignatureRef, app.Install.Digest) {
		drifts = append(drifts, fmt.Sprintf("app %s signature_ref does not bind install digest %s", app.ID, app.Install.Digest))
	}
	foundContractImage := false
	for _, image := range app.FrameworkContract.Images {
		contractRepo, contractDigest, err := splitImageDigest(image.Image)
		if err != nil {
			drifts = append(drifts, fmt.Sprintf("app %s framework image %s: %v", app.ID, image.Name, err))
			continue
		}
		if contractRepo != repo {
			continue
		}
		foundContractImage = true
		if contractDigest != app.Install.Digest || image.Digest != app.Install.Digest {
			drifts = append(drifts, fmt.Sprintf("app %s framework image %s digest drift: got %s/%s want %s", app.ID, image.Name, contractDigest, image.Digest, app.Install.Digest))
		}
	}
	if !foundContractImage {
		drifts = append(drifts, fmt.Sprintf("app %s framework_contract.images missing production image for %s", app.ID, repo))
	}
	if app.FrameworkContract.EgressProxy.Required {
		proxy := app.FrameworkContract.EgressProxy
		if _, proxyDigest, err := splitImageDigest(proxy.Image); err != nil {
			drifts = append(drifts, fmt.Sprintf("app %s egress proxy image: %v", app.ID, err))
		} else if proxyDigest != proxy.Digest {
			drifts = append(drifts, fmt.Sprintf("app %s egress proxy digest drift: image has %s, digest has %s", app.ID, proxyDigest, proxy.Digest))
		}
		if proxy.SignatureRef == "" || !strings.Contains(proxy.SignatureRef, proxy.Digest) {
			drifts = append(drifts, fmt.Sprintf("app %s egress proxy signature_ref does not bind digest %s", app.ID, proxy.Digest))
		}
		if proxy.SBOMRef == "" || proxy.VulnerabilityScanRef == "" {
			drifts = append(drifts, fmt.Sprintf("app %s egress proxy missing SBOM or vulnerability scan refs", app.ID))
		}
	}
	return drifts
}

func helmDigestReplacements(apps []registry.AppSpec) (map[string]string, error) {
	replacements := map[string]string{}
	for _, app := range apps {
		repo, digest, err := splitImageDigest(app.Install.Image)
		if err != nil {
			return nil, fmt.Errorf("app %s install image: %w", app.ID, err)
		}
		if digest != app.Install.Digest {
			return nil, fmt.Errorf("app %s install image digest %s does not match install.digest %s", app.ID, digest, app.Install.Digest)
		}
		replacements[repo] = app.Install.Digest
		if app.FrameworkContract.EgressProxy.Required {
			proxy := app.FrameworkContract.EgressProxy
			proxyRepo, proxyDigest, err := splitImageDigest(proxy.Image)
			if err != nil {
				return nil, fmt.Errorf("app %s egress proxy image: %w", app.ID, err)
			}
			if proxyDigest != proxy.Digest {
				return nil, fmt.Errorf("app %s egress proxy image digest %s does not match egress digest %s", app.ID, proxyDigest, proxy.Digest)
			}
			if existing, ok := replacements[proxyRepo]; ok && existing != proxy.Digest {
				return nil, fmt.Errorf("egress proxy digest drift across promoted apps: got %s and %s", existing, proxy.Digest)
			}
			replacements[proxyRepo] = proxy.Digest
		}
	}
	return replacements, nil
}

func replaceDigestLinesAfterRepository(content string, replacements map[string]string) (string, error) {
	repoLine := regexp.MustCompile(`^(\s*)repository:\s*"?([^"\s]+)"?\s*$`)
	digestLine := regexp.MustCompile(`^(\s*)digest:\s*"?sha256:[0-9a-f]{64}"?\s*$`)
	lines := strings.SplitAfter(content, "\n")
	var out strings.Builder
	pendingRepo := ""
	pendingDigest := ""
	applied := map[string]int{}
	for _, line := range lines {
		body := strings.TrimSuffix(line, "\n")
		if pendingRepo != "" && !digestLine.MatchString(body) {
			trimmed := strings.TrimSpace(body)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				return "", fmt.Errorf("repository %s was not followed by a digest line in Helm values", pendingRepo)
			}
		}
		if match := repoLine.FindStringSubmatch(body); match != nil {
			if digest, ok := replacements[match[2]]; ok {
				pendingRepo = match[2]
				pendingDigest = digest
			}
			out.WriteString(line)
			continue
		}
		if pendingRepo != "" {
			if match := digestLine.FindStringSubmatch(body); match != nil {
				suffix := ""
				if strings.HasSuffix(line, "\n") {
					suffix = "\n"
				}
				out.WriteString(match[1] + `digest: "` + pendingDigest + `"` + suffix)
				applied[pendingRepo]++
				pendingRepo = ""
				pendingDigest = ""
				continue
			}
		}
		out.WriteString(line)
	}
	if pendingRepo != "" {
		return "", fmt.Errorf("repository %s was not followed by a digest line in Helm values", pendingRepo)
	}
	var missing []string
	for repo := range replacements {
		if applied[repo] == 0 {
			missing = append(missing, repo)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return "", fmt.Errorf("Helm values missing digest fields for repositories: %s", strings.Join(missing, ", "))
	}
	return out.String(), nil
}

func syncFrameworkContractImages(images []registry.FrameworkImageContractSpec, entry ArtifactEntry) []registry.FrameworkImageContractSpec {
	repo, _, err := splitImageDigest(entry.Image)
	if err != nil {
		return images
	}
	out := append([]registry.FrameworkImageContractSpec{}, images...)
	matched := false
	for i := range out {
		imageRepo, _, err := splitImageDigest(out[i].Image)
		if err != nil || imageRepo != repo {
			continue
		}
		out[i].Image = entry.Image
		out[i].Digest = entry.Digest
		matched = true
	}
	if !matched {
		out = append(out, registry.FrameworkImageContractSpec{
			Name:    entry.AppID + "-production",
			Image:   entry.Image,
			Digest:  entry.Digest,
			Purpose: "production_proof",
		})
	}
	return out
}

func validateSubjectBinding(label, image, digest, subjectName, subjectDigest string) error {
	if subjectName == "" && subjectDigest == "" {
		return nil
	}
	repo, imageDigest, err := splitImageDigest(image)
	if err != nil {
		return fmt.Errorf("%s subject binding: %w", label, err)
	}
	if subjectName != "" && subjectName != repo {
		return fmt.Errorf("%s subject_name %q does not match image repository %q", label, subjectName, repo)
	}
	if subjectDigest != "" && subjectDigest != digest {
		return fmt.Errorf("%s subject_digest %q does not match digest %q", label, subjectDigest, digest)
	}
	if subjectDigest != "" && subjectDigest != imageDigest {
		return fmt.Errorf("%s subject_digest %q does not match image digest %q", label, subjectDigest, imageDigest)
	}
	return nil
}

func splitImageDigest(image string) (string, string, error) {
	parts := strings.Split(image, "@")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", fmt.Errorf("expected immutable image@sha256 digest, got %q", image)
	}
	digest := strings.TrimSpace(parts[1])
	if !registryDigest(digest) {
		return "", "", fmt.Errorf("digest must be sha256:<64 lowercase hex>, got %q", digest)
	}
	return strings.TrimSpace(parts[0]), digest, nil
}

func imageLockPath(root string) string {
	return filepath.Join(root, "registry", "launchpad", "image-lock.json")
}

func helmValuesPath(root string) string {
	return filepath.Join(root, "deploy", "helm-chart", "values.yaml")
}
