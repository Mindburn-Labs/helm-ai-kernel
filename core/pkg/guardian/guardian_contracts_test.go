package guardian

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFinal_ResponseLevelStringObserve(t *testing.T) {
	if ResponseObserve.String() != "OBSERVE" {
		t.Fatalf("want OBSERVE, got %s", ResponseObserve.String())
	}
}

func TestFinal_ResponseLevelStringThrottle(t *testing.T) {
	if ResponseThrottle.String() != "THROTTLE" {
		t.Fatalf("want THROTTLE, got %s", ResponseThrottle.String())
	}
}

func TestFinal_ResponseLevelStringInterrupt(t *testing.T) {
	if ResponseInterrupt.String() != "INTERRUPT" {
		t.Fatalf("want INTERRUPT, got %s", ResponseInterrupt.String())
	}
}

func TestFinal_ResponseLevelStringQuarantine(t *testing.T) {
	if ResponseQuarantine.String() != "QUARANTINE" {
		t.Fatalf("want QUARANTINE, got %s", ResponseQuarantine.String())
	}
}

func TestFinal_ResponseLevelStringFailClosed(t *testing.T) {
	if ResponseFailClosed.String() != "FAIL_CLOSED" {
		t.Fatalf("want FAIL_CLOSED, got %s", ResponseFailClosed.String())
	}
}

func TestFinal_ResponseLevelStringUnknown(t *testing.T) {
	got := ResponseLevel(99).String()
	if got != "UNKNOWN(99)" {
		t.Fatalf("want UNKNOWN(99), got %s", got)
	}
}

func TestFinal_GradedResponseJSON(t *testing.T) {
	gr := GradedResponse{Level: ResponseThrottle, Reason: "rate limit", Duration: time.Second, AllowEffect: false, WindowRate: 5.5}
	data, err := json.Marshal(gr)
	if err != nil {
		t.Fatal(err)
	}
	var gr2 GradedResponse
	if err := json.Unmarshal(data, &gr2); err != nil {
		t.Fatal(err)
	}
	if gr2.Level != ResponseThrottle {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ResponseLevelOrder(t *testing.T) {
	if ResponseObserve >= ResponseThrottle {
		t.Fatal("observe should be < throttle")
	}
	if ResponseThrottle >= ResponseInterrupt {
		t.Fatal("throttle should be < interrupt")
	}
	if ResponseInterrupt >= ResponseQuarantine {
		t.Fatal("interrupt should be < quarantine")
	}
	if ResponseQuarantine >= ResponseFailClosed {
		t.Fatal("quarantine should be < fail_closed")
	}
}

func TestFinal_AllResponseLevelsStringNonempty(t *testing.T) {
	levels := []ResponseLevel{ResponseObserve, ResponseThrottle, ResponseInterrupt, ResponseQuarantine, ResponseFailClosed}
	for _, l := range levels {
		if l.String() == "" {
			t.Fatalf("level %d has empty string", l)
		}
	}
}

func TestFinal_DecisionRequestZeroValue(t *testing.T) {
	var dr DecisionRequest
	if dr.Principal != "" {
		t.Fatal("zero-value request should have empty principal")
	}
}
