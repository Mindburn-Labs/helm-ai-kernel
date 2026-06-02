package arc

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

func TestPackBuilderAppendProofGraphAndFinalize(t *testing.T) {
	graph := proofgraph.NewGraph().WithClock(func() time.Time { return time.Unix(100, 0) })
	if _, err := graph.Append(proofgraph.NodeTypeIntent, []byte(`{"intent":"test"}`), "principal", 1); err != nil {
		t.Fatalf("Append: %v", err)
	}

	builder := NewPackBuilder("mission-1")
	if builder.missionID != "mission-1" {
		t.Fatalf("unexpected mission id %q", builder.missionID)
	}
	if err := builder.AppendProofGraph(graph); err != nil {
		t.Fatalf("AppendProofGraph: %v", err)
	}
	data, err := builder.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	reader := tar.NewReader(bytes.NewReader(data))
	header, err := reader.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if header.Name != "proofgraph/nodes.json" || header.Mode != 0600 {
		t.Fatalf("unexpected tar header: %#v", header)
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Contains(payload, []byte(`"kind":"INTENT"`)) {
		t.Fatalf("expected proofgraph node payload, got %s", payload)
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestAppendProofGraphErrors(t *testing.T) {
	graph := proofgraph.NewGraph()

	restore := replacePackBuilderHooks()
	defer restore()

	marshalNodes = func(any) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}
	if err := NewPackBuilder("mission").AppendProofGraph(graph); err == nil || err.Error() != "marshal failed" {
		t.Fatalf("expected marshal error, got %v", err)
	}
	restore()

	builder := NewPackBuilder("mission")
	builder.writer = fakeArchiveWriter{headerErr: errors.New("header failed")}
	if err := builder.AppendProofGraph(graph); err == nil || err.Error() != "header failed" {
		t.Fatalf("expected header error, got %v", err)
	}

	builder.writer = fakeArchiveWriter{writeErr: errors.New("write failed")}
	if err := builder.AppendProofGraph(graph); err == nil || err.Error() != "write failed" {
		t.Fatalf("expected write error, got %v", err)
	}
}

func TestFinalizeError(t *testing.T) {
	builder := NewPackBuilder("mission")
	builder.writer = fakeArchiveWriter{closeErr: errors.New("close failed")}
	if _, err := builder.Finalize(); err == nil || err.Error() != "close failed" {
		t.Fatalf("expected close error, got %v", err)
	}
}

type fakeArchiveWriter struct {
	headerErr error
	writeErr  error
	closeErr  error
}

func (w fakeArchiveWriter) WriteHeader(*tar.Header) error {
	return w.headerErr
}

func (w fakeArchiveWriter) Write([]byte) (int, error) {
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	return 0, nil
}

func (w fakeArchiveWriter) Close() error {
	return w.closeErr
}

func replacePackBuilderHooks() func() {
	originalNewArchiveWriter := newArchiveWriter
	originalMarshalNodes := marshalNodes
	return func() {
		newArchiveWriter = originalNewArchiveWriter
		marshalNodes = originalMarshalNodes
	}
}
