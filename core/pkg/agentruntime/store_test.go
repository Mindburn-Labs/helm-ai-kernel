package agentruntime

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/translog"
)

func TestStoreRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	events := happyToolTurn(t)

	// Append in two batches; the store assigns seq/prevhash itself.
	res1, err := s.Append("turn-happy", events[0], events[1], events[2])
	if err != nil {
		t.Fatalf("append batch 1: %v", err)
	}
	if res1.FromSeq != 0 || res1.ToSeq != 2 || res1.HeadHash == "" {
		t.Fatalf("bad append result: %+v", res1)
	}
	res2, err := s.Append("turn-happy", events[3:]...)
	if err != nil {
		t.Fatalf("append batch 2: %v", err)
	}
	if res2.FromSeq != 3 || res2.ToSeq != uint64(len(events)-1) {
		t.Fatalf("bad append result: %+v", res2)
	}

	loaded, state, err := s.Load("turn-happy")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !reflect.DeepEqual(loaded, events) {
		t.Fatalf("roundtrip mismatch:\n got %+v\nwant %+v", loaded, events)
	}
	if state.Status != StatusCompleted {
		t.Fatalf("state status = %s", state.Status)
	}
	head, err := s.HeadHash("turn-happy")
	if err != nil {
		t.Fatal(err)
	}
	if head != res2.HeadHash {
		t.Fatalf("head hash %s != append result %s", head, res2.HeadHash)
	}
	if err := s.Verify("turn-happy"); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestStoreAppendGateWritesNothing(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append("turn-g", evCreated("turn-g")); err != nil {
		t.Fatal(err)
	}
	headBefore, err := s.HeadHash("turn-g")
	if err != nil {
		t.Fatal(err)
	}
	// Illegal: a second turn_created. The reducer gate must reject it and
	// no byte may reach disk.
	if _, err := s.Append("turn-g", evCreated("turn-g")); err == nil {
		t.Fatal("illegal append accepted")
	} else if !strings.Contains(err.Error(), "reducer gate") {
		t.Fatalf("error should name the reducer gate: %v", err)
	}
	headAfter, err := s.HeadHash("turn-g")
	if err != nil {
		t.Fatal(err)
	}
	if headBefore != headAfter {
		t.Fatal("rejected append changed the log head")
	}
	loaded, _, err := s.Load("turn-g")
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatalf("log has %d events after rejected append", len(loaded))
	}
}

func readRaw(t *testing.T, dir, turnID string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, turnID+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeRaw(t *testing.T, dir, turnID, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, turnID+".jsonl"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

// TestStoreCorruptionFailsLoud is the corruption matrix: every tampering
// mode must produce a hard error on load. There is no repair path.
func TestStoreCorruptionFailsLoud(t *testing.T) {
	build := func(t *testing.T) (string, string) {
		dir := t.TempDir()
		s, err := OpenStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Append("turn-happy", happyToolTurn(t)...); err != nil {
			t.Fatal(err)
		}
		return dir, readRaw(t, dir, "turn-happy")
	}
	reopen := func(t *testing.T, dir string) *Store {
		t.Helper()
		s, err := OpenStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	t.Run("tampered event byte breaks chain", func(t *testing.T) {
		dir, raw := build(t)
		lines := strings.Split(raw, "\n")
		// Flip a character inside a string value of the first line: the
		// line stays canonical, but the recomputed event hash no longer
		// matches the next event's prev_hash.
		lines[0] = strings.Replace(lines[0], `"agent:test"`, `"agent:eest"`, 1)
		writeRaw(t, dir, "turn-happy", strings.Join(lines, "\n"))
		if err := reopen(t, dir).Verify("turn-happy"); err == nil || !strings.Contains(err.Error(), "hash chain broken") {
			t.Fatalf("want chain failure, got %v", err)
		}
	})

	t.Run("tampered prev_hash breaks chain", func(t *testing.T) {
		dir, raw := build(t)
		lines := strings.Split(raw, "\n")
		// Recompute line 2's canonical form with a forged prev_hash so the
		// line stays canonical but the chain check fails.
		ev, err := decodeCanonicalLine(lines[1])
		if err != nil {
			t.Fatal(err)
		}
		ev.PrevHash = "sha256:" + strings.Repeat("0", 64)
		canon, err := CanonicalBytes(&ev)
		if err != nil {
			t.Fatal(err)
		}
		lines[1] = string(canon)
		writeRaw(t, dir, "turn-happy", strings.Join(lines, "\n"))
		if err := reopen(t, dir).Verify("turn-happy"); err == nil || !strings.Contains(err.Error(), "hash chain broken") {
			t.Fatalf("want chain failure, got %v", err)
		}
	})

	t.Run("truncated final line", func(t *testing.T) {
		dir, raw := build(t)
		writeRaw(t, dir, "turn-happy", raw[:len(raw)-10])
		if err := reopen(t, dir).Verify("turn-happy"); err == nil || !strings.Contains(err.Error(), "newline-terminated") {
			t.Fatalf("want truncation failure, got %v", err)
		}
	})

	t.Run("truncated mid log", func(t *testing.T) {
		dir, raw := build(t)
		lines := strings.Split(raw, "\n")
		writeRaw(t, dir, "turn-happy", strings.Join(lines[:4], "\n")+"\n")
		// Dropping lines leaves a non-terminal prefix: legal! Verification
		// of a prefix must succeed (crash recovery depends on it).
		if err := reopen(t, dir).Verify("turn-happy"); err != nil {
			t.Fatalf("prefix should verify: %v", err)
		}
	})

	t.Run("reordered lines", func(t *testing.T) {
		dir, raw := build(t)
		lines := strings.Split(raw, "\n")
		lines[1], lines[2] = lines[2], lines[1]
		writeRaw(t, dir, "turn-happy", strings.Join(lines, "\n"))
		if err := reopen(t, dir).Verify("turn-happy"); err == nil {
			t.Fatal("reordered log verified")
		}
	})

	t.Run("non-canonical whitespace", func(t *testing.T) {
		dir, raw := build(t)
		lines := strings.Split(raw, "\n")
		lines[0] = strings.Replace(lines[0], `"turn_id":"turn-happy"`, `"turn_id": "turn-happy"`, 1)
		writeRaw(t, dir, "turn-happy", strings.Join(lines, "\n"))
		if err := reopen(t, dir).Verify("turn-happy"); err == nil || !strings.Contains(err.Error(), "canonical form") {
			t.Fatalf("want canonical-form failure, got %v", err)
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		dir, raw := build(t)
		lines := strings.Split(raw, "\n")
		lines[0] = strings.Replace(lines[0], `"turn_created"`, `"evil":1,"turn_created"`, 1)
		writeRaw(t, dir, "turn-happy", strings.Join(lines, "\n"))
		if err := reopen(t, dir).Verify("turn-happy"); err == nil {
			t.Fatal("log with unknown field verified")
		}
	})

	t.Run("well-formed but reducer-illegal event", func(t *testing.T) {
		dir, _ := build(t)
		s := reopen(t, dir)
		// Craft a canonical, correctly-chained but illegal event (an event
		// appended after a terminal turn) by hand and append it behind the
		// store's back.
		head, err := s.HeadHash("turn-happy")
		if err != nil {
			t.Fatal(err)
		}
		loaded, _, err := s.Load("turn-happy")
		if err != nil {
			t.Fatal(err)
		}
		forged := evCreated("turn-happy")
		forged.Seq = uint64(len(loaded))
		forged.PrevHash = head
		canon, err := CanonicalBytes(&forged)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(filepath.Join(dir, "turn-happy.jsonl"), os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(append(canon, '\n')); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if err := reopen(t, dir).Verify("turn-happy"); err == nil || !strings.Contains(err.Error(), "terminal") {
			t.Fatalf("want reducer rejection on read, got %v", err)
		}
	})
}

func TestStoreAnchorIntoTranslog(t *testing.T) {
	dir := t.TempDir()
	anchor, err := translog.Open(filepath.Join(dir, "translog"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(filepath.Join(dir, "turns"), WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	events := happyToolTurn(t)
	res, err := s.Append("turn-happy", events...)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.AnchorLeafIndices) != len(events) {
		t.Fatalf("anchored %d leaves for %d events", len(res.AnchorLeafIndices), len(events))
	}
	if anchor.Size() != uint64(len(events)) {
		t.Fatalf("anchor size = %d, want %d", anchor.Size(), len(events))
	}
	// Every event hash is a leaf, and its inclusion proof verifies against
	// the current tree head.
	root, err := anchor.Root(anchor.Size())
	if err != nil {
		t.Fatal(err)
	}
	for i := range events {
		h, err := HashEvent(&events[i])
		if err != nil {
			t.Fatal(err)
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(h, sha256Prefix))
		if err != nil {
			t.Fatal(err)
		}
		leaf := translog.LeafHash(raw)
		stored, err := anchor.LeafHashAt(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if leaf != stored {
			t.Fatalf("leaf %d mismatch", i)
		}
		proof, err := anchor.InclusionProof(uint64(i), anchor.Size())
		if err != nil {
			t.Fatal(err)
		}
		if err := translog.VerifyInclusion(proof, hex.EncodeToString(root[:])); err != nil {
			t.Fatalf("inclusion proof %d: %v", i, err)
		}
	}
}

func TestStoreAnchorRangeRepair(t *testing.T) {
	dir := t.TempDir()
	turnsDir := filepath.Join(dir, "turns")
	s, err := OpenStore(turnsDir)
	if err != nil {
		t.Fatal(err)
	}
	events := happyToolTurn(t)
	if _, err := s.Append("turn-happy", events...); err != nil {
		t.Fatal(err)
	}
	// Attach an anchor after the fact and anchor the full range.
	anchor, err := translog.Open(filepath.Join(dir, "translog"))
	if err != nil {
		t.Fatal(err)
	}
	s2, err := OpenStore(turnsDir, WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	indices, err := s2.AnchorRange("turn-happy", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(indices) != len(events) {
		t.Fatalf("anchored %d, want %d", len(indices), len(events))
	}
	if anchor.Size() != uint64(len(events)) {
		t.Fatalf("anchor size = %d", anchor.Size())
	}
}

func TestStoreInfraErrorIsNotToolError(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append("turn-i", evCreated("turn-i")); err != nil {
		t.Fatal(err)
	}
	// Make the store directory unwritable and append to a NEW turn: the
	// create must fail as infrastructure, typed so callers can never
	// mistake it for a tool error.
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0700) }()
	_, err = s.Append("turn-i2", evCreated("turn-i2"))
	ie, ok := AsInfraError(err)
	if !ok {
		t.Fatalf("want InfraError, got %T: %v", err, err)
	}
	if ie.Op == "" {
		t.Fatal("InfraError missing op")
	}
}

func TestStoreRejectsPathTraversalTurnID(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"../x", "a/b", "", ".", "a b"} {
		if _, err := s.Append(bad, evCreated("turn-x")); err == nil {
			t.Fatalf("turn_id %q accepted", bad)
		}
	}
}
