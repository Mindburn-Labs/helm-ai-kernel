package publish

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// GitMarkdownPublisher commits published artifacts as markdown files to a git repo.
// It is only called after internal registry promotion and human approval via the
// Override Queue, ensuring the fail-closed guarantee is preserved end-to-end.
type GitMarkdownPublisher struct {
	RepoPath    string
	AuthorName  string
	AuthorEmail string
}

// NewGitMarkdownPublisher creates a GitMarkdownPublisher that writes into repoPath.
func NewGitMarkdownPublisher(repoPath, name, email string) *GitMarkdownPublisher {
	return &GitMarkdownPublisher{
		RepoPath:    repoPath,
		AuthorName:  name,
		AuthorEmail: email,
	}
}

// Publish writes bodyMD as a markdown file under content/research/<slug>.md and
// creates a signed git commit in the configured repository.
func (p *GitMarkdownPublisher) Publish(ctx context.Context, rec *researchruntime.PublicationRecord, bodyMD string) error {
	slug := rec.Slug
	if slug == "" {
		slug = slugify(rec.Title)
	}

	dir := filepath.Join(p.RepoPath, "content", "research")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("git-publish: mkdir: %w", err)
	}

	contentPath := filepath.Join(dir, slug+".md")
	frontmatter := fmt.Sprintf("---\ntitle: %q\ndate: %s\nslug: %s\nhelm_evidence_hash: %s\n---\n\n",
		rec.Title, time.Now().Format("2006-01-02"), slug, rec.EvidencePackHash)

	if err := os.WriteFile(contentPath, []byte(frontmatter+bodyMD), 0644); err != nil {
		return fmt.Errorf("git-publish: write: %w", err)
	}

	gitEnv := append(os.Environ(),
		"GIT_AUTHOR_NAME="+p.AuthorName,
		"GIT_AUTHOR_EMAIL="+p.AuthorEmail,
		"GIT_COMMITTER_NAME="+p.AuthorName,
		"GIT_COMMITTER_EMAIL="+p.AuthorEmail,
	)

	for _, args := range [][]string{
		{"add", contentPath},
		{"commit", "-m", fmt.Sprintf("research: publish %q [evidence: %s]", rec.Title, truncHash(rec.EvidencePackHash))},
	} {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = p.RepoPath
		cmd.Env = gitEnv
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git %s: %w\n%s", args[0], err, out)
		}
	}
	return nil
}

// slugify converts a human-readable title into a URL-safe slug.
func slugify(title string) string {
	s := strings.ToLower(title)
	var b strings.Builder
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r == ' ' || r == '-':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// truncHash returns the first 12 characters of a hash (or the full string if shorter).
func truncHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
