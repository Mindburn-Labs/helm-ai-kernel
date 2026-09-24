package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const constitutionV1 = `# Constitution

## INV-001 Receipts are signed

Every receipt carries a signature.

- verify: ` + "`Makefile`" + `

## INV-002 Decisions are pure

No I/O inside decide.
`

// conceptRepo is a throwaway git repository holding a constitution, so the
// gate is exercised against real commits rather than a mocked history.
type conceptRepo struct {
	t   *testing.T
	dir string
}

func newConceptRepo(t *testing.T) *conceptRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatalf("git is required: %v", err)
	}
	r := &conceptRepo{t: t, dir: t.TempDir()}
	r.git("init", "-q", "-b", "main")
	r.commit(constitutionV1, "seed the constitution")
	return r
}

func (r *conceptRepo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	// Ignore the developer's global config (commit signing, hooks, templates).
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=invcheck", "GIT_AUTHOR_EMAIL=invcheck@example.invalid",
		"GIT_COMMITTER_NAME=invcheck", "GIT_COMMITTER_EMAIL=invcheck@example.invalid",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func (r *conceptRepo) commit(text, msg string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.dir, constitution), []byte(text), 0o644); err != nil {
		r.t.Fatal(err)
	}
	r.git("add", constitution)
	r.git("commit", "-q", "--allow-empty", "-m", msg)
}

func (r *conceptRepo) gate(rng string) int {
	r.t.Helper()
	return runConceptGate([]string{"-root", r.dir, "-range", rng})
}

func TestConceptGateFailsAnUnmarkedInvariantEdit(t *testing.T) {
	r := newConceptRepo(t)
	r.commit(strings.Replace(constitutionV1, "carries a signature", "carries two signatures", 1), "tighten receipts")

	if got := r.gate("HEAD~1..HEAD"); got != 1 {
		t.Fatalf("an INV-001 edit without a CONCEPT-CHANGE marker must fail (exit 1), got %d", got)
	}
}

func TestConceptGatePassesAMarkedInvariantEdit(t *testing.T) {
	r := newConceptRepo(t)
	r.commit(strings.Replace(constitutionV1, "carries a signature", "carries two signatures", 1),
		"tighten receipts\n\nCONCEPT-CHANGE(INV-001)")

	if got := r.gate("HEAD~1..HEAD"); got != 0 {
		t.Fatalf("a marked INV-001 edit must pass, got %d", got)
	}
}

func TestConceptGateFailsAMarkerThatNamesTheWrongInvariant(t *testing.T) {
	r := newConceptRepo(t)
	r.commit(strings.Replace(constitutionV1, "carries a signature", "carries two signatures", 1),
		"tighten receipts\n\nCONCEPT-CHANGE(INV-002)")

	if got := r.gate("HEAD~1..HEAD"); got != 1 {
		t.Fatalf("a marker that does not name INV-001 must fail, got %d", got)
	}
}

func TestConceptGatePassesAProseOnlyEdit(t *testing.T) {
	r := newConceptRepo(t)
	r.commit(strings.Replace(constitutionV1, "# Constitution", "# The constitution", 1), "retitle")

	if got := r.gate("HEAD~1..HEAD"); got != 0 {
		t.Fatalf("an edit outside every INV block needs no marker, got %d", got)
	}
}

func TestConceptGateRejectsAnEmptyRange(t *testing.T) {
	r := newConceptRepo(t)
	r.commit(strings.Replace(constitutionV1, "carries a signature", "carries two signatures", 1), "tighten receipts")

	// HEAD..HEAD is what origin/main..HEAD is on a main checkout: no commits.
	// It inspects nothing, so it must not report PASS.
	if got := r.gate("HEAD..HEAD"); got != 2 {
		t.Fatalf("an empty range must exit 2, got %d", got)
	}
}

func TestConceptGateRejectsAnUnknownRange(t *testing.T) {
	r := newConceptRepo(t)
	if got := r.gate("no-such-ref..HEAD"); got != 2 {
		t.Fatalf("an unresolvable range must exit 2, got %d", got)
	}
}
