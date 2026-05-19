package skillpacks

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var githubDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type GitHubSkillRef struct {
	Owner  string
	Repo   string
	Path   string
	Ref    string
	Digest string
}

func ParseGitHubSkillRef(raw string) (GitHubSkillRef, error) {
	value := strings.TrimPrefix(strings.TrimSpace(raw), "github:")
	digestSplit := strings.Split(value, "#")
	if len(digestSplit) != 2 || !githubDigestPattern.MatchString(digestSplit[1]) {
		return GitHubSkillRef{}, errors.New("GitHub skill ref must include pinned archive digest: github:owner/repo/path@ref#sha256:<64-hex>")
	}
	refSplit := strings.Split(digestSplit[0], "@")
	if len(refSplit) != 2 || strings.TrimSpace(refSplit[1]) == "" {
		return GitHubSkillRef{}, errors.New("GitHub skill ref must include explicit ref")
	}
	if refSplit[1] == "main" || refSplit[1] == "master" || refSplit[1] == "HEAD" {
		return GitHubSkillRef{}, errors.New("mutable GitHub branch refs are denied for SkillPack install")
	}
	parts := strings.Split(refSplit[0], "/")
	if len(parts) < 3 {
		return GitHubSkillRef{}, errors.New("GitHub skill ref must include owner/repo/path")
	}
	return GitHubSkillRef{
		Owner:  parts[0],
		Repo:   parts[1],
		Path:   path.Clean(strings.Join(parts[2:], "/")),
		Ref:    refSplit[1],
		Digest: digestSplit[1],
	}, nil
}

func LoadGitHub(raw string) (SkillPack, error) {
	ref, err := ParseGitHubSkillRef(raw)
	if err != nil {
		return SkillPack{}, err
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/tarball/%s", ref.Owner, ref.Repo, ref.Ref)
	client := &http.Client{Timeout: 60 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return SkillPack{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return SkillPack{}, fmt.Errorf("GitHub skill fetch failed: HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 128<<20))
	if err != nil {
		return SkillPack{}, err
	}
	sum := sha256.Sum256(data)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != ref.Digest {
		return SkillPack{}, fmt.Errorf("GitHub skill archive digest mismatch: got %s", got)
	}
	root, err := extractGitHubSkillArchive(data, ref.Path)
	if err != nil {
		return SkillPack{}, err
	}
	return LoadDir(root)
}

func extractGitHubSkillArchive(data []byte, skillPath string) (string, error) {
	tmp, err := os.MkdirTemp("", "helm-skillpack-github-*")
	if err != nil {
		return "", err
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	prefix := strings.Trim(strings.TrimPrefix(path.Clean(skillPath), "."), "/")
	found := false
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		name := path.Clean(header.Name)
		parts := strings.SplitN(name, "/", 2)
		if len(parts) != 2 {
			continue
		}
		rel := parts[1]
		if prefix != "" {
			if rel != prefix && !strings.HasPrefix(rel, prefix+"/") {
				continue
			}
			rel = strings.TrimPrefix(rel, prefix)
			rel = strings.TrimPrefix(rel, "/")
		}
		if rel == "" {
			continue
		}
		target := filepath.Join(tmp, filepath.FromSlash(rel))
		cleanTmp := filepath.Clean(tmp)
		if !strings.HasPrefix(filepath.Clean(target), cleanTmp+string(filepath.Separator)) {
			return "", errors.New("GitHub skill archive path escape")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return "", err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return "", err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return "", err
			}
			_, copyErr := io.Copy(out, reader)
			closeErr := out.Close()
			if copyErr != nil {
				return "", copyErr
			}
			if closeErr != nil {
				return "", closeErr
			}
			found = true
		case tar.TypeSymlink:
			return "", errors.New("GitHub skill archives may not contain symlinks")
		}
	}
	if !found {
		return "", fmt.Errorf("skill path %q not found in GitHub archive", skillPath)
	}
	return tmp, nil
}
