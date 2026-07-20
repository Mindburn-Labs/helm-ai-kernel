package shadow

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScanFindingsSummariesAndSkips(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "openai.py", "import openai  # sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nANTHROPIC='sk-ant-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'\n")
	writeFile(t, root, "nested/helm.py", "import helm_sdk\n")
	writeFile(t, root, "nested/anthropic.py", "import anthropic\n")
	writeFile(t, root, "parent/helm.go", "import \"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shadow\"\n")
	writeFile(t, root, "parent/child/use.ts", "import OpenAI from 'openai'\n")
	writeFile(t, root, ".mcp.json", "{}\n")
	writeFile(t, root, "node_modules/ignored.py", "import openai\n")
	writeFile(t, root, "README.md", "import openai\n")

	now := time.Unix(1700000000, 0).UTC()
	scanner := NewScanner()
	scanner.Clock = func() time.Time { return now }

	report, err := scanner.Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if report.ScanRoot == "" || !filepath.IsAbs(report.ScanRoot) {
		t.Fatalf("ScanRoot = %q", report.ScanRoot)
	}
	if report.FilesScanned != 6 {
		t.Fatalf("FilesScanned = %d, want 6", report.FilesScanned)
	}
	if report.FilesSkipped != 1 {
		t.Fatalf("FilesSkipped = %d, want 1", report.FilesSkipped)
	}
	if !report.GeneratedAt.Equal(now) || report.ScanDurationMs != 0 {
		t.Fatalf("time fields = generated %s duration %d", report.GeneratedAt, report.ScanDurationMs)
	}

	wantKinds := map[string]string{
		"openai.py:openai":              "helm_absent",
		"openai.py:openai:key":          "api_key",
		"openai.py:anthropic:key":       "api_key",
		".mcp.json:mcp":                 "mcp_config",
		"nested/helm.py:helm":           "sdk_import",
		"nested/anthropic.py:anthropic": "sdk_import",
		"parent/helm.go:helm":           "sdk_import",
		"parent/child/use.ts:openai":    "sdk_import",
	}
	seen := map[string]Finding{}
	for _, finding := range report.Findings {
		key := finding.Path + ":" + finding.Vendor
		if finding.Kind == "api_key" {
			key += ":key"
		}
		seen[key] = finding
		if finding.DetectedAt != now {
			t.Fatalf("DetectedAt for %#v = %s, want %s", finding, finding.DetectedAt, now)
		}
	}
	for key, kind := range wantKinds {
		finding, ok := seen[key]
		if !ok {
			t.Fatalf("missing finding %q in %#v", key, report.Findings)
		}
		if finding.Kind != kind {
			t.Fatalf("finding %q kind = %q, want %q", key, finding.Kind, kind)
		}
	}

	if seen["openai.py:openai"].Severity != "MEDIUM" || !strings.Contains(seen["openai.py:openai"].Note, "no HELM marker") {
		t.Fatalf("openai absence finding = %#v", seen["openai.py:openai"])
	}
	if seen["parent/child/use.ts:openai"].Severity != "LOW" {
		t.Fatalf("HELM-covered child finding = %#v", seen["parent/child/use.ts:openai"])
	}
	if !report.HelmCoverage.Present || report.HelmCoverage.Count != 2 || len(report.HelmCoverage.Paths) != 2 {
		t.Fatalf("HelmCoverage = %#v", report.HelmCoverage)
	}
	if report.SummaryByVendor["openai"] != 3 || report.SummaryByVendor["helm"] != 2 || report.SummaryByVendor["mcp"] != 1 {
		t.Fatalf("SummaryByVendor = %#v", report.SummaryByVendor)
	}
	if report.SummaryBySeverity["MEDIUM"] == 0 || report.SummaryBySeverity["HIGH"] == 0 || report.SummaryBySeverity["INFO"] != 2 {
		t.Fatalf("SummaryBySeverity = %#v", report.SummaryBySeverity)
	}
	for _, key := range []string{"openai.py:openai:key", "openai.py:anthropic:key"} {
		finding := seen[key]
		if strings.Contains(finding.Evidence, "sk-AAAAAAAA") || strings.Contains(finding.Evidence, "sk-ant-BBBBB") {
			t.Fatalf("api key evidence leaked raw secret for %s: %q", key, finding.Evidence)
		}
		if !strings.Contains(finding.Evidence, "[REDACTED_") || !strings.Contains(finding.Evidence, "sha256:") {
			t.Fatalf("api key evidence missing redacted fingerprint for %s: %q", key, finding.Evidence)
		}
	}
	for i := 1; i < len(report.Findings); i++ {
		prev, cur := report.Findings[i-1], report.Findings[i]
		if prev.Path > cur.Path || (prev.Path == cur.Path && prev.Line > cur.Line) {
			t.Fatalf("findings not sorted: %#v", report.Findings)
		}
	}
}

func TestScanErrorAndWalkerBranches(t *testing.T) {
	restore := replaceScannerHooks(t)
	scannerAbs = func(string) (string, error) {
		return "", errors.New("abs failed")
	}
	if _, err := NewScanner().Scan("root"); err == nil || !strings.Contains(err.Error(), "abs failed") {
		t.Fatalf("Scan() abs error = %v", err)
	}
	restore()

	restore = replaceScannerHooks(t)
	scannerWalkDir = func(string, fs.WalkDirFunc) error {
		return errors.New("walk failed")
	}
	if _, err := NewScanner().Scan("root"); err == nil || !strings.Contains(err.Error(), "walk failed") {
		t.Fatalf("Scan() walk error = %v", err)
	}
	restore()

	restore = replaceScannerHooks(t)
	scannerWalkDir = func(root string, fn fs.WalkDirFunc) error {
		if err := fn(filepath.Join(root, "unreadable"), nil, errors.New("permission denied")); err != nil {
			return err
		}
		if err := fn(filepath.Join(root, "nil-entry"), nil, nil); err != nil {
			return err
		}
		return nil
	}
	if _, err := NewScanner().Scan("root"); err == nil || !strings.Contains(err.Error(), "nil directory entry") {
		t.Fatalf("Scan() nil entry error = %v", err)
	}
	restore()

	restore = replaceScannerHooks(t)
	scannerWalkDir = func(root string, fn fs.WalkDirFunc) error {
		if err := fn(root, fakeDirEntry{name: "root", dir: true}, nil); err != nil {
			return err
		}
		if err := fn(filepath.Join(root, "bad.py"), fakeDirEntry{name: "bad.py", infoErr: errors.New("stat failed")}, nil); err != nil {
			return err
		}
		return nil
	}
	report, err := NewScanner().Scan("root")
	if err != nil {
		t.Fatalf("Scan() info error branch returned %v", err)
	}
	if report.FilesSkipped != 1 {
		t.Fatalf("FilesSkipped = %d, want 1", report.FilesSkipped)
	}
	restore()

	root := t.TempDir()
	writeFile(t, root, "large.py", "import openai\n")
	s := NewScanner()
	s.MaxFileBytes = 1
	report, err = s.Scan(root)
	if err != nil {
		t.Fatalf("Scan() large file error = %v", err)
	}
	if report.FilesScanned != 0 || report.FilesSkipped != 1 || len(report.Findings) != 0 {
		t.Fatalf("large file report = %#v", report)
	}
}

func TestHelpersAndDirectScanFileBranches(t *testing.T) {
	s := NewScanner()
	if !s.shouldSkipDir("/repo", filepath.Join("/repo", "node_modules", "pkg")) {
		t.Fatal("shouldSkipDir() did not skip excluded directory")
	}
	if s.shouldSkipDir("/repo", filepath.Join("/repo", "src")) {
		t.Fatal("shouldSkipDir() skipped non-excluded directory")
	}

	restore := replaceScannerHooks(t)
	scannerRel = func(string, string) (string, error) {
		return "", errors.New("rel failed")
	}
	if s.shouldSkipDir("/repo", "/repo/node_modules") {
		t.Fatal("shouldSkipDir() should return false on rel error")
	}
	restore()

	for _, tt := range []struct {
		path string
		want bool
	}{
		{"agent.py", true},
		{"app.TSX", true},
		{"service.mjs", true},
		{"package.json", true},
		{"mcp.yaml", true},
		{"agent.toml", true},
		{"settings.json", true},
		{"plain.json", false},
		{"README.md", false},
	} {
		if got := s.shouldScanFile(tt.path); got != tt.want {
			t.Fatalf("shouldScanFile(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}

	for _, tt := range []struct {
		ext  string
		want string
	}{
		{".py", "python"},
		{".js", "typescript"},
		{".go", "go"},
		{".json", "config"},
		{".txt", "unknown"},
	} {
		if got := languageForExt(tt.ext); got != tt.want {
			t.Fatalf("languageForExt(%q) = %q, want %q", tt.ext, got, tt.want)
		}
	}

	if got := truncateEvidence("  short  ", 20); got != "short" {
		t.Fatalf("truncateEvidence(short) = %q", got)
	}
	long := strings.Repeat("x", 150)
	if got := truncateEvidence(long, 10); len(got) != 12 || !strings.HasSuffix(got, "…") {
		t.Fatalf("truncateEvidence(long) = %q", got)
	}
	for _, tt := range []struct {
		severity string
		want     int
	}{
		{"INFO", 1},
		{"LOW", 2},
		{"MEDIUM", 3},
		{"HIGH", 4},
		{"UNKNOWN", 0},
	} {
		if got := severityRank(tt.severity); got != tt.want {
			t.Fatalf("severityRank(%q) = %d, want %d", tt.severity, got, tt.want)
		}
	}
	if !helmAnywhereAbove("parent/child", map[string]bool{"parent": true}) {
		t.Fatal("helmAnywhereAbove() did not find parent HELM marker")
	}
	if helmAnywhereAbove("parent/child", map[string]bool{"other": true}) {
		t.Fatal("helmAnywhereAbove() found unrelated HELM marker")
	}

	report := &Report{Findings: []Finding{
		{Kind: "sdk_import", Vendor: "vendor", Path: "noguard/app.py", Severity: "HIGH"},
		{Kind: "api_key", Vendor: "openai", Path: "noguard/app.py", Severity: "HIGH"},
		{Kind: "sdk_import", Vendor: "helm", Path: "helm/app.py", Severity: "INFO"},
		{Kind: "other", Vendor: "vendor", Path: "noguard/other.py", Severity: "LOW"},
	}}
	s.annotateHelmAbsence(report)
	if report.Findings[0].Kind != "helm_absent" || !strings.Contains(report.Findings[0].Note, "Agent SDK detected") || report.Findings[0].Severity != "HIGH" {
		t.Fatalf("annotated empty-note finding = %#v", report.Findings[0])
	}
	if report.Findings[1].Kind != "api_key" || report.Findings[2].Kind != "sdk_import" || report.Findings[3].Kind != "other" {
		t.Fatalf("unexpected annotation changes = %#v", report.Findings)
	}

	root := t.TempDir()
	file := writeFile(t, root, "rel.py", "import openai\n")
	direct := &Report{}
	restore = replaceScannerHooks(t)
	scannerRel = func(string, string) (string, error) {
		return "", errors.New("rel failed")
	}
	if err := s.scanFile(file, "relative-root", direct); err != nil {
		t.Fatalf("scanFile() rel fallback error = %v", err)
	}
	if len(direct.Findings) != 1 || direct.Findings[0].Path != file {
		t.Fatalf("scanFile() rel error findings = %#v", direct.Findings)
	}
	restore()

	restore = replaceScannerHooks(t)
	scannerOpen = func(string) (*os.File, error) {
		return nil, errors.New("open failed")
	}
	before := len(direct.Findings)
	if err := s.scanFile(file, root, direct); err == nil {
		t.Fatal("scanFile() open error = nil, want error")
	}
	if len(direct.Findings) != before {
		t.Fatalf("scanFile() open error changed findings: %#v", direct.Findings)
	}
	restore()
}

func TestStrictScannerFailsClosedOnIncompleteCoverage(t *testing.T) {
	t.Run("missing root", func(t *testing.T) {
		s := NewScanner()
		s.RequireComplete = true
		_, err := s.Scan(filepath.Join(t.TempDir(), "missing"))
		if !errors.Is(err, ErrScanCoverageIncomplete) {
			t.Fatalf("strict missing-root error = %v, want coverage error", err)
		}
	})

	t.Run("walk error", func(t *testing.T) {
		restore := replaceScannerHooks(t)
		scannerWalkDir = func(root string, fn fs.WalkDirFunc) error {
			return fn(filepath.Join(root, "unreadable"), nil, errors.New("permission denied"))
		}
		_, err := (&Scanner{RequireComplete: true, MaxFileBytes: 2 * 1024 * 1024, Clock: time.Now}).Scan("root")
		if !errors.Is(err, ErrScanCoverageIncomplete) {
			t.Fatalf("strict walk error = %v, want coverage error", err)
		}
		if strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "unreadable") {
			t.Fatalf("strict walk error leaked source detail: %v", err)
		}
		restore()
	})

	t.Run("stat error", func(t *testing.T) {
		restore := replaceScannerHooks(t)
		scannerWalkDir = func(root string, fn fs.WalkDirFunc) error {
			if err := fn(root, fakeDirEntry{name: "root", dir: true}, nil); err != nil {
				return err
			}
			return fn(filepath.Join(root, "candidate.py"), fakeDirEntry{name: "candidate.py", infoErr: errors.New("stat failed")}, nil)
		}
		_, err := (&Scanner{RequireComplete: true, MaxFileBytes: 2 * 1024 * 1024, Clock: time.Now}).Scan("root")
		if !errors.Is(err, ErrScanCoverageIncomplete) {
			t.Fatalf("strict stat error = %v, want coverage error", err)
		}
		restore()
	})

	t.Run("oversized candidate", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "large.py", "import openai\n")
		s := NewScanner()
		s.RequireComplete = true
		s.MaxFileBytes = 1
		_, err := s.Scan(root)
		if !errors.Is(err, ErrScanCoverageIncomplete) {
			t.Fatalf("strict oversized error = %v, want coverage error", err)
		}
	})

	t.Run("open error", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "candidate.py", "import openai\n")
		restore := replaceScannerHooks(t)
		scannerOpen = func(string) (*os.File, error) { return nil, errors.New("open failed") }
		s := NewScanner()
		s.RequireComplete = true
		_, err := s.Scan(root)
		if !errors.Is(err, ErrScanCoverageIncomplete) {
			t.Fatalf("strict open error = %v, want coverage error", err)
		}
		restore()
	})

	t.Run("long line", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "candidate.py", strings.Repeat("x", 1024*1024+1))
		s := NewScanner()
		s.RequireComplete = true
		_, err := s.Scan(root)
		if !errors.Is(err, ErrScanCoverageIncomplete) {
			t.Fatalf("strict long line error = %v, want coverage error", err)
		}
	})
}

func replaceScannerHooks(t *testing.T) func() {
	t.Helper()

	oldAbs := scannerAbs
	oldWalkDir := scannerWalkDir
	oldRel := scannerRel
	oldOpen := scannerOpen
	restored := false

	restore := func() {
		if restored {
			return
		}
		scannerAbs = oldAbs
		scannerWalkDir = oldWalkDir
		scannerRel = oldRel
		scannerOpen = oldOpen
		restored = true
	}
	t.Cleanup(restore)
	return restore
}

func writeFile(t *testing.T, root, rel, body string) string {
	t.Helper()

	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

type fakeDirEntry struct {
	name    string
	dir     bool
	infoErr error
}

func (e fakeDirEntry) Name() string {
	return e.name
}

func (e fakeDirEntry) IsDir() bool {
	return e.dir
}

func (e fakeDirEntry) Type() fs.FileMode {
	if e.dir {
		return fs.ModeDir
	}
	return 0
}

func (e fakeDirEntry) Info() (fs.FileInfo, error) {
	if e.infoErr != nil {
		return nil, e.infoErr
	}
	return fakeFileInfo{name: e.name, dir: e.dir}, nil
}

type fakeFileInfo struct {
	name string
	dir  bool
}

func (i fakeFileInfo) Name() string {
	return i.name
}

func (i fakeFileInfo) Size() int64 {
	return 0
}

func (i fakeFileInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir
	}
	return 0
}

func (i fakeFileInfo) ModTime() time.Time {
	return time.Time{}
}

func (i fakeFileInfo) IsDir() bool {
	return i.dir
}

func (i fakeFileInfo) Sys() any {
	return nil
}
