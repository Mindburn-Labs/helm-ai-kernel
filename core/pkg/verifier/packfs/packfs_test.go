package packfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

// pack builds a pack directory beside a directory that is not part of it.
func pack(t *testing.T) (dir, outside string) {
	t.Helper()
	root := t.TempDir()
	dir = filepath.Join(root, "pack")
	outside = filepath.Join(root, "outside")
	for _, d := range []string{filepath.Join(dir, "sub"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(dir, "in.txt"), "inside")
	write(t, filepath.Join(dir, "sub", "nested.txt"), "nested")
	write(t, filepath.Join(outside, "out.txt"), "outside")
	return dir, outside
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func open(t *testing.T, dir string) *FS {
	t.Helper()
	p, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRefusesWhatIsNotADirectory(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "absent")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Open of a missing directory = %v, want ErrNotExist", err)
	}
}

// statReplacingRoot performs the real stat and changes the named object
// before handing its metadata back. Opens still use the real os.Root.
type statReplacingRoot struct {
	rootHandle
	name     string
	replace  func() error
	replaced bool
}

func (r *statReplacingRoot) Stat(name string) (fs.FileInfo, error) {
	info, err := r.rootHandle.Stat(name)
	if err == nil && name == r.name && !r.replaced {
		if err := r.replace(); err != nil {
			return nil, err
		}
		r.replaced = true
	}
	return info, err
}

func directoryOperations() map[string]func(*FS, string) error {
	return map[string]func(*FS, string) error{
		"ReadDir": func(p *FS, name string) error {
			_, err := p.ReadDir(name)
			return err
		},
		"Open": func(p *FS, name string) error {
			file, err := p.Open(name)
			if err == nil {
				_ = file.Close()
			}
			return err
		},
	}
}

func TestDirectoryReplacementIsRefused(t *testing.T) {
	for method, run := range directoryOperations() {
		t.Run(method, func(t *testing.T) {
			dir, _ := pack(t)
			p := open(t, dir)
			root := &statReplacingRoot{rootHandle: p.root, name: "sub", replace: func() error {
				if err := os.Rename(filepath.Join(dir, "sub"), filepath.Join(dir, "original")); err != nil {
					return err
				}
				return os.Mkdir(filepath.Join(dir, "sub"), 0o700)
			}}
			p.root = root
			if err := run(p, "sub"); !errors.Is(err, ErrNotRegular) || !strings.Contains(err.Error(), "directory changed") {
				t.Fatalf("%s after directory replacement = %v, want refusal of the changed directory", method, err)
			}
			if !root.replaced {
				t.Fatal("the directory was not replaced after Stat")
			}
		})
	}
}

func TestOpenedDirectoryKeepsItsHandle(t *testing.T) {
	dir, _ := pack(t)
	p := open(t, dir)
	file, err := p.Open("sub")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Rename(filepath.Join(dir, "sub"), filepath.Join(dir, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "sub", "replacement.txt"), "replacement")
	entries, err := file.(fs.ReadDirFile).ReadDir(-1)
	if err != nil || len(entries) != 1 || entries[0].Name() != "nested.txt" {
		t.Fatalf("opened directory lists %v, %v; want the original nested.txt", entries, err)
	}
}

func TestDirectoryNamesUseSlashSeparators(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "a", "b", "nested.txt"), "nested")
	p := open(t, dir)
	methods := map[string]func(string) ([]fs.DirEntry, error){
		"ReadDir": p.ReadDir,
		"Open": func(name string) ([]fs.DirEntry, error) {
			file, err := p.Open(name)
			if err != nil {
				return nil, err
			}
			defer file.Close()
			return file.(fs.ReadDirFile).ReadDir(-1)
		},
	}
	for method, list := range methods {
		t.Run(method+" slash path", func(t *testing.T) {
			entries, err := list("a/b")
			if err != nil || len(entries) != 1 || entries[0].Name() != "nested.txt" {
				t.Fatalf("slash path lists %v, %v; want nested.txt", entries, err)
			}
		})
	}
	if runtime.GOOS != "windows" {
		if err := os.Mkdir(filepath.Join(dir, `a\b`), 0o700); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(dir, `a\b`, "literal.txt"), "literal")
	}
	for method, list := range methods {
		t.Run(method+" backslash name", func(t *testing.T) {
			entries, err := list(`a\b`)
			if runtime.GOOS == "windows" {
				if !errors.Is(err, fs.ErrInvalid) {
					t.Fatalf("backslash name lists %v, %v; want ErrInvalid", entries, err)
				}
			} else if err != nil || len(entries) != 1 || entries[0].Name() != "literal.txt" {
				t.Fatalf("backslash name lists %v, %v; want literal.txt, not the nested directory", entries, err)
			}
		})
	}
}

func TestCleanName(t *testing.T) {
	for name, want := range map[string]string{
		"in.txt":          "in.txt",
		"./in.txt":        "in.txt",
		"sub//nested.txt": "sub/nested.txt",
	} {
		if got, err := CleanName(name); err != nil || got != want {
			t.Errorf("CleanName(%q) = %q, %v; want %q", name, got, err, want)
		}
	}
	for _, name := range []string{"", "/etc/hosts", `\share\x`, "../x", "sub/../in.txt", `sub\..\in.txt`, ".", "./"} {
		if got, err := CleanName(name); !errors.Is(err, ErrOutside) {
			t.Errorf("CleanName(%q) = %q, %v; want ErrOutside", name, got, err)
		}
	}
}

// A name or a link that leaves the pack is refused, whichever method reads it.
func TestReadsStayInsideThePack(t *testing.T) {
	dir, outside := pack(t)
	symlink(t, filepath.Join(outside, "out.txt"), filepath.Join(dir, "abs-out.txt"))
	symlink(t, "../outside/out.txt", filepath.Join(dir, "rel-out.txt"))
	symlink(t, filepath.Join(dir, "in.txt"), filepath.Join(dir, "abs-in.txt"))
	symlink(t, "in.txt", filepath.Join(dir, "rel-in.txt"))
	symlink(t, outside, filepath.Join(dir, "outdir"))
	p := open(t, dir)

	for _, name := range []string{"abs-out.txt", "rel-out.txt", "abs-in.txt", "outdir/out.txt", "../outside/out.txt", "/etc/hosts", `sub\..\in.txt`} {
		if _, err := p.ReadFile(name); !errors.Is(err, ErrOutside) {
			t.Errorf("ReadFile(%q) = %v, want ErrOutside", name, err)
		}
		if _, err := p.Stat(name); !errors.Is(err, ErrOutside) {
			t.Errorf("Stat(%q) = %v, want ErrOutside", name, err)
		}
	}
	if _, err := p.ReadDir("outdir"); !errors.Is(err, ErrOutside) {
		t.Errorf("ReadDir(outdir) = %v, want ErrOutside", err)
	}
	if _, err := p.Lstat("../outside"); !errors.Is(err, ErrOutside) {
		t.Errorf("Lstat(../outside) = %v, want ErrOutside", err)
	}

	// A relative link that stays inside the pack is followed.
	if data, err := p.ReadFile("rel-in.txt"); err != nil || string(data) != "inside" {
		t.Fatalf("ReadFile(rel-in.txt) = %q, %v", data, err)
	}
	if info, err := p.Lstat("rel-in.txt"); err != nil || info.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("Lstat(rel-in.txt) = %v, %v; want the link itself", info, err)
	}
}

func TestOnlyRegularFilesAreRead(t *testing.T) {
	dir, _ := pack(t)
	p := open(t, dir)
	if _, err := p.ReadFile("sub"); !errors.Is(err, ErrNotRegular) || !strings.Contains(err.Error(), "a directory") {
		t.Fatalf("ReadFile of a directory = %v, want ErrNotRegular", err)
	}
	if _, err := p.ReadFile("absent.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadFile of a missing file = %v, want ErrNotExist", err)
	}
}

func TestReadFileLimit(t *testing.T) {
	dir, _ := pack(t)
	p := open(t, dir)
	if data, err := p.ReadFileLimit("in.txt", 6); err != nil || string(data) != "inside" {
		t.Fatalf("ReadFileLimit at the size = %q, %v", data, err)
	}
	if _, err := p.ReadFileLimit("in.txt", 5); !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "5 bytes") {
		t.Fatalf("ReadFileLimit under the size = %v, want ErrTooLarge naming the limit", err)
	}
	if got := Bytes(64 << 20); got != "64 MiB" {
		t.Fatalf("Bytes(64 MiB) = %q", got)
	}
}

func TestCheckCase(t *testing.T) {
	dir, _ := pack(t)
	p := open(t, dir)
	if err := p.CheckCase("sub/nested.txt"); err != nil {
		t.Fatalf("CheckCase of the exact spelling = %v", err)
	}
	if err := p.CheckCase("SUB/nested.txt"); !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "another letter case") {
		t.Fatalf("CheckCase of another letter case = %v, want ErrNotExist naming the spelling", err)
	}
	if err := p.CheckCase("sub/absent.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("CheckCase of a missing name = %v, want ErrNotExist", err)
	}
	if err := p.CheckCase("../x"); !errors.Is(err, ErrOutside) {
		t.Fatalf("CheckCase(../x) = %v, want ErrOutside", err)
	}
}

// FS is an fs.FS: fs.WalkDir and the standard file system test see the pack.
func TestFSIsAFileSystem(t *testing.T) {
	dir, _ := pack(t)
	p := open(t, dir)
	var names []string
	if err := p.Walk(".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		names = append(names, name)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names, ","); got != ".,in.txt,sub,sub/nested.txt" {
		t.Fatalf("walk = %s", got)
	}
	file, err := p.Open("in.txt")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(file)
	_ = file.Close()
	if string(data) != "inside" {
		t.Fatalf("Open read %q", data)
	}
	if err := fstest.TestFS(p, "in.txt", "sub/nested.txt"); err != nil {
		t.Fatal(err)
	}
}

// NF3: a name the directory does not list was compared with every name it
// does list, so a manifest naming n absent files in a directory of n files
// cost n*n comparisons: 45 s for 80,000. A miss is now one map lookup on the
// case-folded name, which still finds a spelling in another letter case.
func TestCheckCase_AMissCostsOneLookup(t *testing.T) {
	const names = 80_000
	dir := t.TempDir()
	logs := filepath.Join(dir, "06_LOGS")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	// Creating and removing 80,000 files one by one is slow on some file
	// systems; spread both over goroutines.
	forEachName := func(do func(name string) error) {
		var wg sync.WaitGroup
		errs := make(chan error, 16)
		for worker := range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := worker; i < names; i += 16 {
					if err := do(filepath.Join(logs, fmt.Sprintf("file-%05d.log", i))); err != nil {
						errs <- err
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
	}
	forEachName(func(name string) error { return os.WriteFile(name, nil, 0o600) })
	t.Cleanup(func() { forEachName(os.Remove) })
	write(t, filepath.Join(dir, "k.txt"), "")
	p := open(t, dir)

	done := make(chan error, 1)
	go func() {
		for i := range names {
			if err := p.CheckCase(fmt.Sprintf("06_LOGS/absent-%05d.log", i)); !errors.Is(err, fs.ErrNotExist) || strings.Contains(err.Error(), "letter case") {
				done <- fmt.Errorf("CheckCase of absent name %d = %v, want a plain ErrNotExist", i, err)
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("CheckCase of %d absent names in a directory of %d took longer than 10 s", names, names)
	}

	// The folded lookup finds what strings.EqualFold matches, and names the
	// spelling the directory lists.
	for name, listed := range map[string]string{
		"06_LOGS/FILE-00042.LOG": "06_LOGS/file-00042.log",
		"06_logs/file-00042.log": "06_LOGS",
		"K.txt":                  "k.txt", // KELVIN SIGN folds to k
	} {
		err := p.CheckCase(name)
		if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "another letter case") || !strings.Contains(err.Error(), strconv.Quote(listed)) {
			t.Errorf("CheckCase(%q) = %v, want ErrNotExist naming %q in another letter case", name, err, listed)
		}
	}
	if err := p.CheckCase("06_LOGS/file-00042.log"); err != nil {
		t.Errorf("CheckCase of the exact spelling = %v", err)
	}
}
