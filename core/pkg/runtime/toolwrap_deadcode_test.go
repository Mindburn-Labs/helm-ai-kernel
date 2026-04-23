package runtime

import (
	"testing"
	"time"
)

func TestToolWrapper_WithClock_IsReachable(t *testing.T) {
	w := NewToolWrapper("tool", 1*time.Second).WithClock(func() time.Time {
		return time.Unix(0, 0).UTC()
	})

	res := w.Execute("in", func(input interface{}) (interface{}, error) {
		return "out", nil
	})
	if res == nil || !res.Success {
		t.Fatalf("expected success result, got %+v", res)
	}
}

func TestClassifiedError_Error_IsReachable(t *testing.T) {
	e := &ClassifiedError{
		Category: ErrCatInternal,
		Code:     "INTERNAL",
		Message:  "boom",
	}
	if e.Error() == "" {
		t.Fatal("expected non-empty string")
	}
}
