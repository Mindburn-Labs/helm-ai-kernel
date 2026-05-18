package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSkillsSearchAndInspectFirstParty(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSkillsCmd([]string{"search", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("search code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "helm/repo-auditor") {
		t.Fatalf("first-party repo auditor missing: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runSkillsCmd([]string{"inspect", "helm/repo-auditor", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("inspect code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "This skill does not grant tool permissions.") {
		t.Fatalf("authority boundary missing: %s", stdout.String())
	}
}

func TestSkillsInstallRepoScopeAndRevoke(t *testing.T) {
	repoRoot := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := runSkillsCmd([]string{"install", "helm/repo-auditor", "--agent", "codex", "--scope", "repo", "--repo-root", repoRoot, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("install code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(filepath.Join(repoRoot, ".agents", "skills", "helm", "repo-auditor", "SKILL.md")); err != nil {
		t.Fatalf("projected skill missing: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("install json: %v", err)
	}
	if payload["verdict"] != "ALLOW" {
		t.Fatalf("install verdict = %+v", payload)
	}

	stdout.Reset()
	stderr.Reset()
	code = runSkillsCmd([]string{"revoke", "helm/repo-auditor", "--repo-root", repoRoot, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("revoke code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(repoRoot, ".agents", "skills", "helm", "repo-auditor", "SKILL.md")); !os.IsNotExist(err) {
		t.Fatalf("projected skill should be removed, stat err=%v", err)
	}
}

func TestSkillsUserScopeEscalates(t *testing.T) {
	repoRoot := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := runSkillsCmd([]string{"install", "helm/repo-auditor", "--agent", "codex", "--scope", "user", "--repo-root", repoRoot, "--json"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("user-scope install should return non-zero escalation")
	}
	if !strings.Contains(stdout.String(), "ERR_GLOBAL_SKILL_INSTALL_DENIED") {
		t.Fatalf("expected global/user denial reason, stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}
