package modelgw

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSSESplitsEventsAndKeepsTheirBytes(t *testing.T) {
	stream := "event: message_start\ndata: {\"type\":\"message_start\"}\n\n" +
		": keep-alive\n\n" +
		"event: ping\r\ndata: {\"type\": \"ping\"}\r\n\r\n" +
		"data: one\ndata: two\n\n" +
		"data: [DONE]\n\n"
	r := newSSEReader(strings.NewReader(stream), 1<<20)
	var raws strings.Builder
	var got []sseEvent
	for {
		ev, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		raws.Write(ev.Raw)
		got = append(got, ev)
	}
	if raws.String() != stream {
		t.Fatalf("the events do not reassemble into the stream:\n%q\n%q", raws.String(), stream)
	}
	if len(got) != 5 {
		t.Fatalf("%d events, want 5: %+v", len(got), got)
	}
	if got[0].Name != "message_start" || string(got[0].Data) != `{"type":"message_start"}` {
		t.Fatalf("event 0 = %+v", got[0])
	}
	if got[1].Name != "" || got[1].Data != nil {
		t.Fatalf("a comment is an event with no name and no data: %+v", got[1])
	}
	if got[2].Name != "ping" || string(got[2].Data) != `{"type": "ping"}` {
		t.Fatalf("a CRLF event = %+v", got[2])
	}
	if string(got[3].Data) != "one\ntwo" {
		t.Fatalf("multi-line data = %q", got[3].Data)
	}
	if string(got[4].Data) != "[DONE]" {
		t.Fatalf("last event = %+v", got[4])
	}
}

func TestSSEReportsATruncatedStreamAndBoundsAnEvent(t *testing.T) {
	// Ends inside an event: the provider dropped the connection.
	r := newSSEReader(strings.NewReader("event: a\ndata: 1\n\nevent: b\ndata: 2"), 1<<20)
	if _, err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Next(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a stream that ends inside an event: %v", err)
	}
	// Ends between events: a clean end.
	r = newSSEReader(strings.NewReader("data: 1\n\n"), 1<<20)
	if _, err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("a clean end: %v", err)
	}
	// One event past the bound is refused, not buffered.
	r = newSSEReader(strings.NewReader("data: "+strings.Repeat("x", 5000)+"\n\n"), 1024)
	if _, err := r.Next(); !errors.Is(err, errEventTooLarge) {
		t.Fatalf("an oversized event: %v", err)
	}
	// Blank lines between events end nothing.
	r = newSSEReader(strings.NewReader("\n\ndata: 1\n\n"), 1<<20)
	ev, err := r.Next()
	if err != nil || string(ev.Data) != "1" || string(ev.Raw) != "data: 1\n\n" {
		t.Fatalf("leading blank lines: %+v, %v", ev, err)
	}
}
