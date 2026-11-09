package actuators

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestValidIDRefusesWhatCouldEscapeAPathOrACommandLine(t *testing.T) {
	for _, ok := range []string{"sbx-1", "i3x9k2.m", "A_b-c.d", strings.Repeat("a", 128)} {
		if !ValidID(ok) {
			t.Errorf("%q was refused", ok)
		}
	}
	for _, bad := range []string{"", "-rf", ".hidden", "a/b", "../x", "a b", "a;b", "a\nb", "a%2fb", "a?x=1", "é", strings.Repeat("a", 129)} {
		if ValidID(bad) {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestACallErrorIsFoundThroughWrapping(t *testing.T) {
	inner := &CallError{Provider: "e2b", Status: 422, Refused: true, Detail: "POST /sandboxes: status 422"}
	wrapped := fmt.Errorf("e2b: create failed: %w", inner)
	got := AsCallError(wrapped)
	if got != inner || !got.Refused || got.Error() != "e2b: POST /sandboxes: status 422" {
		t.Fatalf("AsCallError = %+v", got)
	}
	if AsCallError(errors.New("plain")) != nil || AsCallError(nil) != nil {
		t.Fatal("an error that wraps no CallError has none")
	}
}
