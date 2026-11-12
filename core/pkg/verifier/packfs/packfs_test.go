package packfs

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
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
