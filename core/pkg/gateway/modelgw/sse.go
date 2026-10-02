package modelgw

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

// errEventTooLarge: one server-sent event is larger than the gateway buffers.
var errEventTooLarge = errors.New("a server-sent event is larger than the gateway buffers")

// sseEvent is one server-sent event: its bytes exactly as received, so it can
// be forwarded verbatim, and the two fields the gateway reads.
type sseEvent struct {
	// Raw is the event with its line terminators, up to and including the
	// blank line that ends it. Comment lines (": keep-alive") are part of it.
	Raw []byte
	// Name is the event: field, empty for an unnamed event.
	Name string
	// Data is the data: lines joined with a newline, nil when there are none.
	Data []byte
}

// sseReader splits a text/event-stream body into events. It accepts the "\n"
// and "\r\n" line endings providers use.
type sseReader struct {
	br  *bufio.Reader
	max int
}

func newSSEReader(r io.Reader, maxEvent int) *sseReader {
	return &sseReader{br: bufio.NewReaderSize(r, 32<<10), max: maxEvent}
}

// Next returns the next event. It returns io.EOF when the stream ends between
// events and io.ErrUnexpectedEOF when it ends inside one, which a provider
// does when it drops the connection.
func (s *sseReader) Next() (sseEvent, error) {
	var ev sseEvent
	var data [][]byte
	started := false
	for {
		line, err := s.readLine()
		if len(line) > 0 {
			ev.Raw = append(ev.Raw, line...)
			if len(ev.Raw) > s.max {
				return sseEvent{}, errEventTooLarge
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && started {
				return sseEvent{}, io.ErrUnexpectedEOF
			}
			if errors.Is(err, io.EOF) && len(ev.Raw) > 0 {
				return sseEvent{}, io.ErrUnexpectedEOF
			}
			return sseEvent{}, err
		}
		text := bytes.TrimRight(line, "\r\n")
		if len(text) == 0 {
			// A blank line ends an event. Leading blank lines end nothing.
			if len(ev.Raw) == len(line) {
				ev.Raw = ev.Raw[:0]
				continue
			}
			if data != nil {
				ev.Data = bytes.Join(data, []byte("\n"))
			}
			return ev, nil
		}
		started = true
		if text[0] == ':' {
			continue
		}
		field, value, _ := bytes.Cut(text, []byte(":"))
		value = bytes.TrimPrefix(value, []byte(" "))
		switch string(field) {
		case "event":
			ev.Name = string(value)
		case "data":
			data = append(data, append([]byte(nil), value...))
		}
	}
}

// readLine returns one line with its terminator, bounded by the event limit.
func (s *sseReader) readLine() ([]byte, error) {
	var line []byte
	for {
		chunk, err := s.br.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > s.max {
			return nil, errEventTooLarge
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, err
	}
}
