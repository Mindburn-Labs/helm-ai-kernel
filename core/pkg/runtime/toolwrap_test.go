package runtime

import (
	"errors"
	"testing"
	"time"
)

func TestToolWrapperSuccess(t *testing.T) {
	w := NewToolWrapper("test-tool", 5*time.Second)
	result := w.Execute("input", func(in interface{}) (interface{}, error) {
		return "output", nil
	})

	if !result.Success {
		t.Fatal("expected success")
	}
	if result.InputHash == "" || result.OutputHash == "" {
		t.Fatal("expected input and output hashes")
	}
}

func TestToolWrapperError(t *testing.T) {
	w := NewToolWrapper("test-tool", 5*time.Second)
	result := w.Execute("input", func(in interface{}) (interface{}, error) {
		return nil, errors.New("permission denied")
	})

	if result.Success {
		t.Fatal("expected failure")
	}
	if result.Error.Category != ErrCatPermission {
		t.Fatalf("expected PERMISSION, got %s", result.Error.Category)
	}
}

func TestToolWrapperTimeout(t *testing.T) {
	w := NewToolWrapper("slow-tool", time.Nanosecond) // very short timeout
	result := w.Execute("input", func(in interface{}) (interface{}, error) {
		time.Sleep(time.Millisecond)
		return "late", nil
	})

	if result.Success {
		t.Fatal("expected timeout failure")
	}
	if result.Error.Category != ErrCatTimeout {
		t.Fatalf("expected TIMEOUT, got %s", result.Error.Category)
	}
}

func TestToolWrapperResults(t *testing.T) {
	w := NewToolWrapper("tool", 5*time.Second)
	w.Execute("a", func(in interface{}) (interface{}, error) { return "1", nil })
	w.Execute("b", func(in interface{}) (interface{}, error) { return "2", nil })

	if len(w.Results()) != 2 {
		t.Fatalf("expected 2 results, got %d", len(w.Results()))
	}
}

func TestErrorTaxonomyClassification(t *testing.T) {
	cases := []struct {
		msg      string
		expected ErrorCategory
	}{
		{"connection timeout", ErrCatTimeout},
		{"rate limit exceeded", ErrCatRateLimit},
		{"forbidden", ErrCatPermission},
		{"resource not found", ErrCatNotFound},
		{"validation error", ErrCatValidation},
		{"temporary failure, please retry", ErrCatTransient},
		{"unknown crash error", ErrCatInternal},
	}

	for _, tc := range cases {
		ce := ClassifyError("tool", errors.New(tc.msg))
		if ce.Category != tc.expected {
			t.Errorf("for %q: expected %s, got %s", tc.msg, tc.expected, ce.Category)
		}
	}
}
