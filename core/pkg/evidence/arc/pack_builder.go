package arc

import (
	"archive/tar"
	"bytes"
	"encoding/json"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

// PackBuilder constructs the final EvidencePack archive representing an ARC attempt.
type PackBuilder struct {
	missionID string
	buffer    *bytes.Buffer
	writer    *tar.Writer
}

func NewPackBuilder(missionID string) *PackBuilder {
	buf := new(bytes.Buffer)
	return &PackBuilder{
		missionID: missionID,
		buffer:    buf,
		writer:    tar.NewWriter(buf),
	}
}

// AppendProofGraph locks the graph's terminal state into the archive.
func (p *PackBuilder) AppendProofGraph(graph *proofgraph.Graph) error {
	nodes := graph.AllNodes()
	data, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	
	hdr := &tar.Header{
		Name: "proofgraph/nodes.json",
		Mode: 0600,
		Size: int64(len(data)),
	}
	if err := p.writer.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = p.writer.Write(data)
	return err
}

// Finalize closes the archive and returns the immutable byte stream.
func (p *PackBuilder) Finalize() ([]byte, error) {
	if err := p.writer.Close(); err != nil {
		return nil, err
	}
	return p.buffer.Bytes(), nil
}
