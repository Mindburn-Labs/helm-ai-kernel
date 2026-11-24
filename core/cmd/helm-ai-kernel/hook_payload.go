// quantum_posture: the oversized payload digest is a classical SHA-256
// commitment to the bytes read.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"strings"
)

// hookMaxInputBytes bounds what the hook reads from standard input. A client
// may run a call whose hook outlives its timeout, so a payload larger than
// this is not read and classified: it is denied with a receipt.
const hookMaxInputBytes = 4 << 20

type preToolPayload struct {
	ToolName       string         `json:"tool_name"`
	ToolNameCamel  string         `json:"toolName"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolInputCamel map[string]any `json:"toolInput"`
	Args           map[string]any `json:"args"`
	SessionID      string         `json:"session_id"`
	CWD            string         `json:"cwd"`
}

// hookOversizedPayload is what the hook knows of a payload over
// hookMaxInputBytes: the SHA-256 of the bytes it read and how many there
// were, and the tool when the payload named it within its first
// hookOversizedToolScanBytes.
type hookOversizedPayload struct {
	sha256 string
	bytes  int
	tool   string
}

func (*hookOversizedPayload) Error() string { return errHookInputTooLarge.Error() }

func (*hookOversizedPayload) Unwrap() error { return errHookInputTooLarge }

// hookOversizedToolScanBytes is how much of an oversized payload is kept to
// look for the tool name, which clients send ahead of the tool input.
const hookOversizedToolScanBytes = 64 << 10

// hookPayloadReader digests every byte the decoder reads and keeps the first
// hookOversizedToolScanBytes of them.
type hookPayloadReader struct {
	source io.Reader
	digest hash.Hash
	head   bytes.Buffer
	read   int
}

func (r *hookPayloadReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	if n > 0 {
		r.digest.Write(p[:n])
		if room := hookOversizedToolScanBytes - r.head.Len(); room > 0 {
			r.head.Write(p[:min(n, room)])
		}
		r.read += n
	}
	return n, err
}

// decodePreToolPayload decodes the first JSON value on standard input. It
// reads no further than that value, so a client that leaves standard input
// open gets its answer, and no further than hookMaxInputBytes+1 bytes: a
// payload past the limit is reported as a *hookOversizedPayload.
func decodePreToolPayload(stdin io.Reader) (preToolPayload, error) {
	var payload preToolPayload
	reader := &hookPayloadReader{source: io.LimitReader(stdin, hookMaxInputBytes+1), digest: sha256.New()}
	dec := json.NewDecoder(reader)
	dec.UseNumber()
	err := dec.Decode(&payload)
	if dec.InputOffset() > hookMaxInputBytes || (err != nil && reader.read > hookMaxInputBytes) {
		return preToolPayload{}, &hookOversizedPayload{
			sha256: "sha256:" + hex.EncodeToString(reader.digest.Sum(nil)),
			bytes:  reader.read,
			tool:   payloadToolName(reader.head.Bytes()),
		}
	}
	if err != nil {
		return payload, fmt.Errorf("decode hook payload: %w", err)
	}
	if payload.ToolName == "" {
		payload.ToolName = payload.ToolNameCamel
	}
	if payload.ToolInput == nil {
		payload.ToolInput = payload.ToolInputCamel
	}
	if payload.ToolInput == nil {
		payload.ToolInput = payload.Args
	}
	if payload.ToolInput == nil {
		payload.ToolInput = map[string]any{}
	}
	return payload, nil
}

// payloadToolName reads the tool name from the start of a payload that may
// be cut off: the top-level tool_name, or toolName when tool_name is absent,
// provided it comes before the first value that does not fit.
func payloadToolName(head []byte) string {
	dec := json.NewDecoder(bytes.NewReader(head))
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return ""
	}
	camel := ""
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			break
		}
		key, _ := token.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			break
		}
		var name string
		if key != "tool_name" && key != "toolName" || json.Unmarshal(value, &name) != nil {
			continue
		}
		if key == "tool_name" {
			return strings.TrimSpace(name)
		}
		camel = strings.TrimSpace(name)
	}
	return camel
}
