package kernel

import (
	"context"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 1-5: CSNF type coverage
// ---------------------------------------------------------------------------

func TestClosing_CSNF_NormalizeString(t *testing.T) {
	tr := NewCSNFTransformer()
	cases := []struct {
		name  string
		input any
	}{
		{"plain_ascii", "hello"},
		{"empty_string", ""},
		{"unicode_nfc", "\u00e9"}, // e-acute
		{"digits_string", "12345"},
		{"special_chars", "a\tb\nc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tr.Transform(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if _, ok := out.(string); !ok {
				t.Fatalf("expected string, got %T", out)
			}
		})
	}
}

func TestClosing_CSNF_NormalizeInteger(t *testing.T) {
	tr := NewCSNFTransformer()
	cases := []struct {
		name  string
		input any
	}{
		{"float_zero", float64(0)},
		{"float_positive", float64(42)},
		{"float_negative", float64(-100)},
		{"float_max_safe", float64(9007199254740991)},
		{"float_min_safe", float64(-9007199254740991)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tr.Transform(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if _, ok := out.(int64); !ok {
				t.Fatalf("expected int64, got %T", out)
			}
		})
	}
}

func TestClosing_CSNF_NormalizeFractional_Rejected(t *testing.T) {
	tr := NewCSNFTransformer()
	cases := []struct {
		name  string
		input float64
	}{
		{"half", 0.5},
		{"pi", 3.14},
		{"negative_frac", -2.7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tr.Transform(tc.input)
			if err == nil {
				t.Fatal("expected error for fractional number")
			}
		})
	}
}

func TestClosing_CSNF_NormalizeBool(t *testing.T) {
	tr := NewCSNFTransformer()
	t.Run("true", func(t *testing.T) {
		out, err := tr.Transform(true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != true {
			t.Fatalf("got %v", out)
		}
	})
	t.Run("false", func(t *testing.T) {
		out, err := tr.Transform(false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != false {
			t.Fatalf("got %v", out)
		}
	})
	t.Run("nil", func(t *testing.T) {
		out, err := tr.Transform(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != nil {
			t.Fatalf("got %v", out)
		}
	})
}

func TestClosing_CSNF_NormalizeObject(t *testing.T) {
	tr := NewCSNFTransformer()
	cases := []struct {
		name  string
		input map[string]any
	}{
		{"empty_map", map[string]any{}},
		{"string_value", map[string]any{"key": "value"}},
		{"int_value", map[string]any{"key": float64(42)}},
		{"nested", map[string]any{"a": map[string]any{"b": "c"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tr.Transform(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if _, ok := out.(map[string]any); !ok {
				t.Fatalf("expected map, got %T", out)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 6-10: NondeterminismSource coverage
// ---------------------------------------------------------------------------

func TestClosing_NondeterminismSource_AllSources(t *testing.T) {
	sources := []struct {
		source NondeterminismSource
		name   string
	}{
		{NDSourceLLM, "LLM"},
		{NDSourceNetwork, "NETWORK"},
		{NDSourceRandom, "RANDOM"},
		{NDSourceExternal, "EXTERNAL_API"},
		{NDSourceTiming, "TIMING"},
		{NDSourceUserInput, "USER_INPUT"},
	}
	for _, tc := range sources {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.source) != tc.name {
				t.Fatalf("got %q, want %q", tc.source, tc.name)
			}
		})
	}
}

func TestClosing_NondeterminismTracker_CaptureAllSources(t *testing.T) {
	tracker := NewNondeterminismTracker()
	sources := []NondeterminismSource{NDSourceLLM, NDSourceNetwork, NDSourceRandom, NDSourceExternal, NDSourceTiming, NDSourceUserInput}
	for _, src := range sources {
		t.Run(string(src), func(t *testing.T) {
			bound := tracker.Capture("run-1", src, "desc", "in-hash", "out-hash", "")
			if bound == nil {
				t.Fatal("bound should not be nil")
			}
			if bound.Source != src {
				t.Fatalf("got source %v, want %v", bound.Source, src)
			}
		})
	}
}

func TestClosing_NondeterminismTracker_Receipt(t *testing.T) {
	tracker := NewNondeterminismTracker()
	tracker.Capture("run-A", NDSourceLLM, "llm call", "in", "out", "seed1")
	tracker.Capture("run-A", NDSourceRandom, "random", "in2", "out2", "seed2")
	t.Run("receipt_exists", func(t *testing.T) {
		receipt, err := tracker.Receipt("run-A")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if receipt == nil {
			t.Fatal("receipt should not be nil")
		}
	})
	t.Run("total_bounds", func(t *testing.T) {
		receipt, _ := tracker.Receipt("run-A")
		if receipt.TotalBounds != 2 {
			t.Fatalf("got %d bounds, want 2", receipt.TotalBounds)
		}
	})
	t.Run("content_hash_set", func(t *testing.T) {
		receipt, _ := tracker.Receipt("run-A")
		if receipt.ContentHash == "" {
			t.Fatal("content hash should not be empty")
		}
	})
	t.Run("missing_run_errors", func(t *testing.T) {
		_, err := tracker.Receipt("nonexistent")
		if err == nil {
			t.Fatal("expected error for missing run")
		}
	})
}

func TestClosing_NondeterminismTracker_BoundsForRun(t *testing.T) {
	tracker := NewNondeterminismTracker()
	tracker.Capture("run-X", NDSourceLLM, "test", "a", "b", "")
	t.Run("has_bounds", func(t *testing.T) {
		bounds := tracker.BoundsForRun("run-X")
		if len(bounds) != 1 {
			t.Fatalf("got %d bounds, want 1", len(bounds))
		}
	})
	t.Run("empty_run", func(t *testing.T) {
		bounds := tracker.BoundsForRun("empty-run")
		if len(bounds) != 0 {
			t.Fatalf("got %d bounds, want 0", len(bounds))
		}
	})
	t.Run("bound_fields_set", func(t *testing.T) {
		bounds := tracker.BoundsForRun("run-X")
		if bounds[0].BoundID == "" {
			t.Fatal("bound ID should not be empty")
		}
	})
}

func TestClosing_NondeterminismBound_ContentHash(t *testing.T) {
	tracker := NewNondeterminismTracker()
	b := tracker.Capture("r1", NDSourceLLM, "test", "in", "out", "seed")
	t.Run("has_sha256_prefix", func(t *testing.T) {
		if len(b.ContentHash) < 7 || b.ContentHash[:7] != "sha256:" {
			t.Fatalf("expected sha256: prefix, got %q", b.ContentHash)
		}
	})
	t.Run("hash_length", func(t *testing.T) {
		// sha256: prefix + 64 hex chars
		if len(b.ContentHash) != 7+64 {
			t.Fatalf("unexpected hash length: %d", len(b.ContentHash))
		}
	})
	t.Run("different_bounds_different_hashes", func(t *testing.T) {
		b2 := tracker.Capture("r1", NDSourceNetwork, "test2", "in2", "out2", "")
		if b.ContentHash == b2.ContentHash {
			t.Fatal("different bounds should have different hashes")
		}
	})
}

// ---------------------------------------------------------------------------
// 11-17: Scheduler priority combos
// ---------------------------------------------------------------------------

func TestClosing_Scheduler_PriorityCombos(t *testing.T) {
	s := NewInMemoryScheduler()
	defer s.Close()
	ctx := context.Background()

	priorities := []int{0, 1, 5, 10, 100}
	for _, p := range priorities {
		t.Run("priority_"+string(rune('0'+p%10)), func(t *testing.T) {
			err := s.Schedule(ctx, &SchedulerEvent{
				EventID:   "evt-" + string(rune('A'+p%26)),
				EventType: "test",
				Priority:  p,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestClosing_Scheduler_NextReturnsByPriority(t *testing.T) {
	s := NewInMemoryScheduler()
	defer s.Close()
	ctx := context.Background()
	now := time.Now()

	_ = s.Schedule(ctx, &SchedulerEvent{EventID: "low", EventType: "test", Priority: 10, ScheduledAt: now})
	_ = s.Schedule(ctx, &SchedulerEvent{EventID: "high", EventType: "test", Priority: 0, ScheduledAt: now})

	t.Run("high_first", func(t *testing.T) {
		evt, err := s.Next(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt.EventID != "high" {
			t.Fatalf("got %s, want high", evt.EventID)
		}
	})
	t.Run("low_second", func(t *testing.T) {
		evt, err := s.Next(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt.EventID != "low" {
			t.Fatalf("got %s, want low", evt.EventID)
		}
	})
	t.Run("empty_after", func(t *testing.T) {
		if s.Len() != 0 {
			t.Fatalf("expected empty scheduler, got %d", s.Len())
		}
	})
}

func TestClosing_Scheduler_Peek(t *testing.T) {
	s := NewInMemoryScheduler()
	defer s.Close()
	ctx := context.Background()

	t.Run("empty_peek_nil", func(t *testing.T) {
		evt, err := s.Peek(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt != nil {
			t.Fatal("expected nil peek on empty scheduler")
		}
	})

	_ = s.Schedule(ctx, &SchedulerEvent{EventID: "a", EventType: "test", Priority: 0})
	t.Run("nonempty_peek", func(t *testing.T) {
		evt, err := s.Peek(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt == nil {
			t.Fatal("expected non-nil")
		}
	})
	t.Run("peek_does_not_remove", func(t *testing.T) {
		if s.Len() != 1 {
			t.Fatalf("peek should not remove, got len %d", s.Len())
		}
	})
}

func TestClosing_Scheduler_SnapshotHash(t *testing.T) {
	s := NewInMemoryScheduler()
	defer s.Close()
	ctx := context.Background()

	t.Run("empty_hash", func(t *testing.T) {
		h := s.SnapshotHash()
		if h == "" {
			t.Fatal("hash should not be empty even for empty scheduler")
		}
	})
	_ = s.Schedule(ctx, &SchedulerEvent{EventID: "x", EventType: "test"})
	t.Run("nonempty_hash", func(t *testing.T) {
		h := s.SnapshotHash()
		if h == "" {
			t.Fatal("hash should not be empty")
		}
	})
	t.Run("hash_changes", func(t *testing.T) {
		h1 := s.SnapshotHash()
		_ = s.Schedule(ctx, &SchedulerEvent{EventID: "y", EventType: "test"})
		h2 := s.SnapshotHash()
		if h1 == h2 {
			t.Fatal("hash should change after adding event")
		}
	})
}

func TestClosing_Scheduler_Close(t *testing.T) {
	s := NewInMemoryScheduler()
	ctx := context.Background()
	_ = s.Schedule(ctx, &SchedulerEvent{EventID: "a"})
	s.Close()
	t.Run("schedule_after_close_errors", func(t *testing.T) {
		err := s.Schedule(ctx, &SchedulerEvent{EventID: "b"})
		if err == nil {
			t.Fatal("expected error after close")
		}
	})
	t.Run("next_drains_remaining", func(t *testing.T) {
		evt, err := s.Next(ctx)
		if err != nil {
			t.Fatalf("should drain remaining: %v", err)
		}
		if evt.EventID != "a" {
			t.Fatalf("got %s", evt.EventID)
		}
	})
	t.Run("next_after_drain_errors", func(t *testing.T) {
		_, err := s.Next(ctx)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestClosing_Scheduler_SequenceNumbers(t *testing.T) {
	s := NewInMemoryScheduler()
	defer s.Close()
	ctx := context.Background()

	_ = s.Schedule(ctx, &SchedulerEvent{EventID: "first"})
	_ = s.Schedule(ctx, &SchedulerEvent{EventID: "second"})
	_ = s.Schedule(ctx, &SchedulerEvent{EventID: "third"})

	e1, _ := s.Next(ctx)
	e2, _ := s.Next(ctx)
	e3, _ := s.Next(ctx)

	t.Run("monotonic_seq_1_2", func(t *testing.T) {
		if e2.SequenceNum <= e1.SequenceNum {
			t.Fatal("sequence numbers should be monotonic")
		}
	})
	t.Run("monotonic_seq_2_3", func(t *testing.T) {
		if e3.SequenceNum <= e2.SequenceNum {
			t.Fatal("sequence numbers should be monotonic")
		}
	})
	t.Run("starts_at_one", func(t *testing.T) {
		if e1.SequenceNum != 1 {
			t.Fatalf("first seq = %d, want 1", e1.SequenceNum)
		}
	})
}

func TestClosing_Scheduler_SortKeyGeneration(t *testing.T) {
	s := NewInMemoryScheduler()
	defer s.Close()
	ctx := context.Background()

	_ = s.Schedule(ctx, &SchedulerEvent{EventID: "e1", EventType: "type1"})
	e, _ := s.Next(ctx)
	t.Run("sort_key_nonempty", func(t *testing.T) {
		if e.SortKey == "" {
			t.Fatal("sort key should be generated")
		}
	})
	t.Run("sort_key_deterministic", func(t *testing.T) {
		_ = s.Schedule(ctx, &SchedulerEvent{EventID: "e1", EventType: "type1"})
		e2, _ := s.Next(ctx)
		if e.SortKey != e2.SortKey {
			t.Fatal("same inputs should produce same sort key")
		}
	})
	t.Run("different_inputs_different_keys", func(t *testing.T) {
		_ = s.Schedule(ctx, &SchedulerEvent{EventID: "e2", EventType: "type2"})
		e3, _ := s.Next(ctx)
		if e.SortKey == e3.SortKey {
			t.Fatal("different inputs should produce different sort keys")
		}
	})
}

// ---------------------------------------------------------------------------
// 18-24: Freeze states
// ---------------------------------------------------------------------------

func TestClosing_FreezeController_InitialState(t *testing.T) {
	fc := NewFreezeController()
	t.Run("not_frozen", func(t *testing.T) {
		if fc.IsFrozen() {
			t.Fatal("should not be frozen initially")
		}
	})
	t.Run("state_details", func(t *testing.T) {
		frozen, principal, _ := fc.FreezeState()
		if frozen {
			t.Fatal("should not be frozen")
		}
		if principal != "" {
			t.Fatalf("principal should be empty, got %q", principal)
		}
	})
	t.Run("empty_receipts", func(t *testing.T) {
		if len(fc.Receipts()) != 0 {
			t.Fatal("should have no receipts")
		}
	})
}

func TestClosing_FreezeController_FreezeUnfreeze(t *testing.T) {
	fc := NewFreezeController()
	r1, err := fc.Freeze("admin")
	t.Run("freeze_succeeds", func(t *testing.T) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if r1 == nil {
			t.Fatal("receipt should not be nil")
		}
	})
	t.Run("is_frozen", func(t *testing.T) {
		if !fc.IsFrozen() {
			t.Fatal("should be frozen")
		}
	})
	t.Run("double_freeze_errors", func(t *testing.T) {
		_, err := fc.Freeze("admin2")
		if err == nil {
			t.Fatal("double freeze should error")
		}
	})
	r2, _ := fc.Unfreeze("admin")
	t.Run("unfreeze_succeeds", func(t *testing.T) {
		if r2 == nil {
			t.Fatal("receipt should not be nil")
		}
		if fc.IsFrozen() {
			t.Fatal("should not be frozen after unfreeze")
		}
	})
	t.Run("double_unfreeze_errors", func(t *testing.T) {
		_, err := fc.Unfreeze("admin")
		if err == nil {
			t.Fatal("double unfreeze should error")
		}
	})
}

func TestClosing_FreezeController_Receipts(t *testing.T) {
	fc := NewFreezeController()
	fc.Freeze("a")
	fc.Unfreeze("a")
	fc.Freeze("b")
	fc.Unfreeze("b")
	receipts := fc.Receipts()
	t.Run("four_receipts", func(t *testing.T) {
		if len(receipts) != 4 {
			t.Fatalf("got %d, want 4", len(receipts))
		}
	})
	t.Run("alternating_actions", func(t *testing.T) {
		if receipts[0].Action != "freeze" || receipts[1].Action != "unfreeze" {
			t.Fatal("actions should alternate")
		}
	})
	t.Run("content_hashes_set", func(t *testing.T) {
		for i, r := range receipts {
			if r.ContentHash == "" {
				t.Fatalf("receipt %d has empty hash", i)
			}
		}
	})
}

func TestClosing_FreezeController_WithClock(t *testing.T) {
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fc := NewFreezeController().WithClock(func() time.Time { return fixedTime })
	r, _ := fc.Freeze("admin")
	t.Run("uses_injected_clock", func(t *testing.T) {
		if !r.Timestamp.Equal(fixedTime) {
			t.Fatalf("got %v, want %v", r.Timestamp, fixedTime)
		}
	})
	t.Run("receipt_hash_deterministic", func(t *testing.T) {
		if r.ContentHash == "" {
			t.Fatal("content hash should not be empty")
		}
	})
	t.Run("state_timestamp", func(t *testing.T) {
		_, _, ts := fc.FreezeState()
		if !ts.Equal(fixedTime) {
			t.Fatalf("got %v, want %v", ts, fixedTime)
		}
	})
}

func TestClosing_FreezeController_ReceiptContentHash(t *testing.T) {
	fc := NewFreezeController()
	r1, _ := fc.Freeze("a")
	fc.Unfreeze("a")
	r2, _ := fc.Freeze("a")
	t.Run("different_freeze_different_hash", func(t *testing.T) {
		if r1.ContentHash == r2.ContentHash {
			t.Fatal("hashes should differ due to different timestamps")
		}
	})
	t.Run("hash_nonempty", func(t *testing.T) {
		if r1.ContentHash == "" || r2.ContentHash == "" {
			t.Fatal("hashes should not be empty")
		}
	})
	t.Run("hash_hex_length", func(t *testing.T) {
		if len(r1.ContentHash) != 64 {
			t.Fatalf("expected 64 hex chars, got %d", len(r1.ContentHash))
		}
	})
}

func TestClosing_FreezeController_CopySemantics(t *testing.T) {
	fc := NewFreezeController()
	fc.Freeze("admin")
	fc.Unfreeze("admin")
	r1 := fc.Receipts()
	r2 := fc.Receipts()
	t.Run("independent_copies", func(t *testing.T) {
		if &r1[0] == &r2[0] {
			t.Fatal("receipts should be independent copies")
		}
	})
	t.Run("same_content", func(t *testing.T) {
		if r1[0].Action != r2[0].Action {
			t.Fatal("copies should have same content")
		}
	})
	t.Run("same_length", func(t *testing.T) {
		if len(r1) != len(r2) {
			t.Fatal("copies should have same length")
		}
	})
}

// ---------------------------------------------------------------------------
// 25-30: Kill switch operations
// ---------------------------------------------------------------------------

func TestClosing_AgentKillSwitch_KillRevive(t *testing.T) {
	ks := NewAgentKillSwitch()
	r, err := ks.Kill("agent-1", "admin", "misbehavior")
	t.Run("kill_succeeds", func(t *testing.T) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if r == nil {
			t.Fatal("receipt should not be nil")
		}
	})
	t.Run("is_killed", func(t *testing.T) {
		if !ks.IsKilled("agent-1") {
			t.Fatal("agent should be killed")
		}
	})
	t.Run("double_kill_errors", func(t *testing.T) {
		_, err := ks.Kill("agent-1", "admin", "again")
		if err == nil {
			t.Fatal("double kill should error")
		}
	})
	r2, _ := ks.Revive("agent-1", "admin")
	t.Run("revive_succeeds", func(t *testing.T) {
		if r2 == nil {
			t.Fatal("receipt should not be nil")
		}
		if ks.IsKilled("agent-1") {
			t.Fatal("agent should not be killed after revive")
		}
	})
}

func TestClosing_AgentKillSwitch_MultipleAgents(t *testing.T) {
	ks := NewAgentKillSwitch()
	agents := []string{"a1", "a2", "a3", "a4", "a5"}
	for _, id := range agents {
		ks.Kill(id, "admin", "test")
	}
	t.Run("all_killed", func(t *testing.T) {
		for _, id := range agents {
			if !ks.IsKilled(id) {
				t.Fatalf("agent %s should be killed", id)
			}
		}
	})
	t.Run("list_killed_count", func(t *testing.T) {
		listed := ks.ListKilled()
		if len(listed) != 5 {
			t.Fatalf("got %d, want 5", len(listed))
		}
	})
	t.Run("not_killed_returns_false", func(t *testing.T) {
		if ks.IsKilled("nonexistent") {
			t.Fatal("nonexistent agent should not be killed")
		}
	})
}

func TestClosing_AgentKillSwitch_Receipts(t *testing.T) {
	ks := NewAgentKillSwitch()
	ks.Kill("a1", "admin", "reason1")
	ks.Revive("a1", "admin")
	receipts := ks.Receipts()
	t.Run("two_receipts", func(t *testing.T) {
		if len(receipts) != 2 {
			t.Fatalf("got %d, want 2", len(receipts))
		}
	})
	t.Run("kill_then_revive", func(t *testing.T) {
		if receipts[0].Action != "KILL" {
			t.Fatalf("first action = %s, want KILL", receipts[0].Action)
		}
		if receipts[1].Action != "REVIVE" {
			t.Fatalf("second action = %s, want REVIVE", receipts[1].Action)
		}
	})
	t.Run("hashes_set", func(t *testing.T) {
		for i, r := range receipts {
			if r.ContentHash == "" {
				t.Fatalf("receipt %d has empty hash", i)
			}
		}
	})
}

func TestClosing_AgentKillSwitch_ReviveNotKilledErrors(t *testing.T) {
	ks := NewAgentKillSwitch()
	t.Run("revive_unknown_errors", func(t *testing.T) {
		_, err := ks.Revive("unknown", "admin")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("kill_then_revive_then_revive_errors", func(t *testing.T) {
		ks.Kill("a1", "admin", "reason")
		ks.Revive("a1", "admin")
		_, err := ks.Revive("a1", "admin")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("empty_id", func(t *testing.T) {
		// Empty ID is technically valid
		_, err := ks.Kill("", "admin", "reason")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestClosing_AgentKillSwitch_WithClock(t *testing.T) {
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ks := NewAgentKillSwitch().WithKillSwitchClock(func() time.Time { return fixedTime })
	r, _ := ks.Kill("agent-1", "admin", "test")
	t.Run("uses_injected_clock", func(t *testing.T) {
		if !r.Timestamp.Equal(fixedTime) {
			t.Fatalf("got %v, want %v", r.Timestamp, fixedTime)
		}
	})
	t.Run("receipt_deterministic", func(t *testing.T) {
		if r.ContentHash == "" {
			t.Fatal("hash should be set")
		}
	})
	t.Run("receipt_action", func(t *testing.T) {
		if r.Action != "KILL" {
			t.Fatalf("got %s, want KILL", r.Action)
		}
	})
}

// ---------------------------------------------------------------------------
// 31-37: Context guard fingerprints
// ---------------------------------------------------------------------------

func TestClosing_ContextGuard_WithFingerprint(t *testing.T) {
	cg := NewContextGuardWithFingerprint("test-fp-123")
	t.Run("boot_fingerprint", func(t *testing.T) {
		if cg.BootFingerprint() != "test-fp-123" {
			t.Fatalf("got %q", cg.BootFingerprint())
		}
	})
	t.Run("validate_match", func(t *testing.T) {
		err := cg.Validate("test-fp-123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("validate_mismatch", func(t *testing.T) {
		err := cg.Validate("different-fp")
		if err == nil {
			t.Fatal("expected mismatch error")
		}
	})
}

func TestClosing_ContextGuard_EmptyFingerprint(t *testing.T) {
	cg := NewContextGuardWithFingerprint("")
	t.Run("passthrough_any", func(t *testing.T) {
		err := cg.Validate("anything")
		if err == nil {
			t.Log("empty boot fingerprint is pass-through")
		}
	})
	t.Run("passthrough_empty", func(t *testing.T) {
		err := cg.Validate("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("boot_fingerprint_empty", func(t *testing.T) {
		if cg.BootFingerprint() != "" {
			t.Fatalf("expected empty, got %q", cg.BootFingerprint())
		}
	})
}

func TestClosing_ContextGuard_Stats(t *testing.T) {
	cg := NewContextGuardWithFingerprint("fp")
	cg.Validate("fp")
	cg.Validate("wrong")
	cg.Validate("fp")
	t.Run("validation_count", func(t *testing.T) {
		v, _ := cg.Stats()
		if v != 3 {
			t.Fatalf("got %d, want 3", v)
		}
	})
	t.Run("mismatch_count", func(t *testing.T) {
		_, m := cg.Stats()
		if m != 1 {
			t.Fatalf("got %d, want 1", m)
		}
	})
	t.Run("initial_stats_zero", func(t *testing.T) {
		cg2 := NewContextGuardWithFingerprint("fp2")
		v, m := cg2.Stats()
		if v != 0 || m != 0 {
			t.Fatalf("expected 0,0 got %d,%d", v, m)
		}
	})
}

func TestClosing_ContextGuard_MismatchError(t *testing.T) {
	cg := NewContextGuardWithFingerprint("aaaa1111aaaa2222aaaa3333aaaa4444")
	err := cg.Validate("bbbb1111bbbb2222bbbb3333bbbb4444")
	t.Run("is_mismatch_error", func(t *testing.T) {
		if err == nil {
			t.Fatal("expected error")
		}
		_, ok := err.(*ContextMismatchError)
		if !ok {
			t.Fatalf("expected *ContextMismatchError, got %T", err)
		}
	})
	t.Run("error_message", func(t *testing.T) {
		if err.Error() == "" {
			t.Fatal("error message should not be empty")
		}
	})
	t.Run("error_fields", func(t *testing.T) {
		cme := err.(*ContextMismatchError)
		if cme.BootFingerprint == "" || cme.CurrentFingerprint == "" {
			t.Fatal("fingerprint fields should be set")
		}
	})
}

func TestClosing_ContextGuard_NewContextGuard(t *testing.T) {
	cg := NewContextGuard()
	t.Run("has_boot_fingerprint", func(t *testing.T) {
		if cg.BootFingerprint() == "" {
			t.Fatal("boot fingerprint should not be empty")
		}
	})
	t.Run("fingerprint_length", func(t *testing.T) {
		fp := cg.BootFingerprint()
		if len(fp) != 64 {
			t.Fatalf("expected 64 hex chars, got %d", len(fp))
		}
	})
	t.Run("validate_current_passes", func(t *testing.T) {
		err := cg.ValidateCurrent()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestClosing_ContextGuard_WithClock(t *testing.T) {
	fixedTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cg := NewContextGuardWithFingerprint("fp").WithClock(func() time.Time { return fixedTime })
	err := cg.Validate("wrong")
	t.Run("uses_clock_in_error", func(t *testing.T) {
		cme := err.(*ContextMismatchError)
		if !cme.DetectedAt.Equal(fixedTime) {
			t.Fatalf("got %v, want %v", cme.DetectedAt, fixedTime)
		}
	})
	t.Run("returns_context_guard", func(t *testing.T) {
		if cg == nil {
			t.Fatal("WithClock should return non-nil")
		}
	})
	t.Run("fingerprint_unchanged", func(t *testing.T) {
		if cg.BootFingerprint() != "fp" {
			t.Fatalf("fingerprint changed after WithClock")
		}
	})
}

func TestClosing_ContextGuard_DeterministicFingerprint(t *testing.T) {
	cg1 := NewContextGuard()
	cg2 := NewContextGuard()
	t.Run("same_env_same_fingerprint", func(t *testing.T) {
		if cg1.BootFingerprint() != cg2.BootFingerprint() {
			t.Fatal("same environment should produce same fingerprint")
		}
	})
	t.Run("hex_encoded", func(t *testing.T) {
		fp := cg1.BootFingerprint()
		for _, c := range fp {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("non-hex char in fingerprint: %c", c)
			}
		}
	})
	t.Run("sha256_length", func(t *testing.T) {
		if len(cg1.BootFingerprint()) != 64 {
			t.Fatalf("got length %d", len(cg1.BootFingerprint()))
		}
	})
}

// ---------------------------------------------------------------------------
// 38-44: CSNF additional types and profiles
// ---------------------------------------------------------------------------

func TestClosing_CSNF_ProfileIDs(t *testing.T) {
	t.Run("csnf_v1", func(t *testing.T) {
		if CSNFProfileID != "csnf-v1" {
			t.Fatalf("got %q", CSNFProfileID)
		}
	})
	t.Run("canonical", func(t *testing.T) {
		if CanonicalProfileID != "csnf-v1+jcs-v1" {
			t.Fatalf("got %q", CanonicalProfileID)
		}
	})
	t.Run("both_set", func(t *testing.T) {
		if CSNFProfileID == "" || CanonicalProfileID == "" {
			t.Fatal("profile IDs should not be empty")
		}
	})
}

func TestClosing_CSNF_ArrayKinds(t *testing.T) {
	t.Run("ordered", func(t *testing.T) {
		if CSNFArrayKindOrdered != "ORDERED" {
			t.Fatalf("got %q", CSNFArrayKindOrdered)
		}
	})
	t.Run("set", func(t *testing.T) {
		if CSNFArrayKindSet != "SET" {
			t.Fatalf("got %q", CSNFArrayKindSet)
		}
	})
	t.Run("distinct", func(t *testing.T) {
		if CSNFArrayKindOrdered == CSNFArrayKindSet {
			t.Fatal("array kinds should be distinct")
		}
	})
}

func TestClosing_CSNF_WithArrayMeta(t *testing.T) {
	tr := NewCSNFTransformer()
	t.Run("chaining", func(t *testing.T) {
		result := tr.WithArrayMeta("/items", CSNFArrayMeta{Kind: CSNFArrayKindSet})
		if result != tr {
			t.Fatal("WithArrayMeta should return same transformer")
		}
	})
	t.Run("meta_stored", func(t *testing.T) {
		if _, ok := tr.ArrayMeta["/items"]; !ok {
			t.Fatal("meta should be stored")
		}
	})
	t.Run("meta_kind", func(t *testing.T) {
		if tr.ArrayMeta["/items"].Kind != CSNFArrayKindSet {
			t.Fatal("kind should be SET")
		}
	})
}

func TestClosing_CSNF_NormalizeArray(t *testing.T) {
	tr := NewCSNFTransformer()
	cases := []struct {
		name  string
		input []any
	}{
		{"empty", []any{}},
		{"strings", []any{"b", "a", "c"}},
		{"ints", []any{float64(3), float64(1), float64(2)}},
		{"mixed", []any{"hello", float64(42), true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tr.Transform(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			arr, ok := out.([]any)
			if !ok {
				t.Fatalf("expected []any, got %T", out)
			}
			if len(arr) != len(tc.input) {
				t.Fatalf("length mismatch: got %d, want %d", len(arr), len(tc.input))
			}
		})
	}
}

func TestClosing_CSNF_NormalizeJSON(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"simple_object", `{"key":"value"}`},
		{"integer", `42`},
		{"string", `"hello"`},
		{"array", `[1,2,3]`},
		{"null", `null`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := CSNFNormalizeJSON([]byte(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(out) == 0 {
				t.Fatal("output should not be empty")
			}
		})
	}
}

func TestClosing_CSNF_ValidateCompliance(t *testing.T) {
	t.Run("compliant_integer", func(t *testing.T) {
		issues := ValidateCSNFCompliance(float64(42))
		if len(issues) != 0 {
			t.Fatalf("expected 0 issues, got %d", len(issues))
		}
	})
	t.Run("noncompliant_fractional", func(t *testing.T) {
		issues := ValidateCSNFCompliance(float64(3.14))
		if len(issues) == 0 {
			t.Fatal("expected issues for fractional")
		}
	})
	t.Run("compliant_string", func(t *testing.T) {
		issues := ValidateCSNFCompliance("hello")
		if len(issues) != 0 {
			t.Fatalf("expected 0 issues, got %d", len(issues))
		}
	})
	t.Run("compliant_map", func(t *testing.T) {
		issues := ValidateCSNFCompliance(map[string]any{"key": "value"})
		if len(issues) != 0 {
			t.Fatalf("expected 0 issues, got %d", len(issues))
		}
	})
}

func TestClosing_CSNFNormalize_Convenience(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		out, err := CSNFNormalize("test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != "test" {
			t.Fatalf("got %v", out)
		}
	})
	t.Run("nil", func(t *testing.T) {
		out, err := CSNFNormalize(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != nil {
			t.Fatalf("got %v", out)
		}
	})
	t.Run("integer", func(t *testing.T) {
		out, err := CSNFNormalize(float64(100))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != int64(100) {
			t.Fatalf("got %v (%T)", out, out)
		}
	})
}

// ---------------------------------------------------------------------------
// 45-50: ErrSchedulerClosed, Limiter, EventLog, etc.
// ---------------------------------------------------------------------------

func TestClosing_ErrSchedulerClosed_Error(t *testing.T) {
	t.Run("message", func(t *testing.T) {
		if ErrSchedulerClosed.Error() != "scheduler closed" {
			t.Fatalf("got %q", ErrSchedulerClosed.Error())
		}
	})
	t.Run("implements_error", func(t *testing.T) {
		var err error = ErrSchedulerClosed
		if err == nil {
			t.Fatal("should implement error")
		}
	})
	t.Run("string_cast", func(t *testing.T) {
		s := string(ErrSchedulerClosed)
		if s != "scheduler closed" {
			t.Fatalf("got %q", s)
		}
	})
}

func TestClosing_NewCSNFTransformer_Fresh(t *testing.T) {
	tr := NewCSNFTransformer()
	t.Run("not_nil", func(t *testing.T) {
		if tr == nil {
			t.Fatal("should not be nil")
		}
	})
	t.Run("empty_array_meta", func(t *testing.T) {
		if len(tr.ArrayMeta) != 0 {
			t.Fatalf("expected empty ArrayMeta, got %d", len(tr.ArrayMeta))
		}
	})
	t.Run("array_meta_not_nil", func(t *testing.T) {
		if tr.ArrayMeta == nil {
			t.Fatal("ArrayMeta should be initialized")
		}
	})
}

func TestClosing_NondeterminismTracker_WithClock(t *testing.T) {
	fixedTime := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	tracker := NewNondeterminismTracker().WithClock(func() time.Time { return fixedTime })
	b := tracker.Capture("run-1", NDSourceLLM, "test", "in", "out", "")
	t.Run("uses_clock", func(t *testing.T) {
		if !b.CapturedAt.Equal(fixedTime) {
			t.Fatalf("got %v, want %v", b.CapturedAt, fixedTime)
		}
	})
	t.Run("returns_tracker", func(t *testing.T) {
		if tracker == nil {
			t.Fatal("should not be nil")
		}
	})
	t.Run("bound_set", func(t *testing.T) {
		if b.BoundID == "" {
			t.Fatal("bound ID should not be empty")
		}
	})
}

func TestClosing_NondeterminismTracker_MultipleRuns(t *testing.T) {
	tracker := NewNondeterminismTracker()
	tracker.Capture("run-A", NDSourceLLM, "a", "in1", "out1", "")
	tracker.Capture("run-B", NDSourceNetwork, "b", "in2", "out2", "")
	tracker.Capture("run-A", NDSourceRandom, "c", "in3", "out3", "seed")
	t.Run("run_A_has_two", func(t *testing.T) {
		bounds := tracker.BoundsForRun("run-A")
		if len(bounds) != 2 {
			t.Fatalf("got %d, want 2", len(bounds))
		}
	})
	t.Run("run_B_has_one", func(t *testing.T) {
		bounds := tracker.BoundsForRun("run-B")
		if len(bounds) != 1 {
			t.Fatalf("got %d, want 1", len(bounds))
		}
	})
	t.Run("independent_receipts", func(t *testing.T) {
		rA, _ := tracker.Receipt("run-A")
		rB, _ := tracker.Receipt("run-B")
		if rA.ContentHash == rB.ContentHash {
			t.Fatal("different runs should have different receipt hashes")
		}
	})
}

func TestClosing_Scheduler_Len(t *testing.T) {
	s := NewInMemoryScheduler()
	defer s.Close()
	ctx := context.Background()

	t.Run("initially_zero", func(t *testing.T) {
		if s.Len() != 0 {
			t.Fatalf("got %d", s.Len())
		}
	})
	_ = s.Schedule(ctx, &SchedulerEvent{EventID: "a"})
	_ = s.Schedule(ctx, &SchedulerEvent{EventID: "b"})
	t.Run("after_two_adds", func(t *testing.T) {
		if s.Len() != 2 {
			t.Fatalf("got %d, want 2", s.Len())
		}
	})
	s.Next(ctx)
	t.Run("after_one_next", func(t *testing.T) {
		if s.Len() != 1 {
			t.Fatalf("got %d, want 1", s.Len())
		}
	})
}
