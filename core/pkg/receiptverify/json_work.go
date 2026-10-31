// quantum_posture: resource preflight adds no signature or trust semantics.
package receiptverify

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Adapter parsing budgets protect the persistent WASM instance before the
// legacy parser constructs recursive diagnostics. The native CLI retains its
// original parser. These limits reject input; they never normalize signed data.
const (
	MaxJSONDepth      = 64
	MaxJSONTokens     = 100000
	MaxJSONKeyBytes   = 256
	MaxJSONTokenBytes = 64 << 10
)

type jsonFrame struct{ object, key bool }

func validateJSONWork(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	stack := make([]jsonFrame, 0, MaxJSONDepth)
	value := func() error {
		if len(stack) > 0 && stack[len(stack)-1].object {
			if stack[len(stack)-1].key {
				return errors.New("JSON object member name is required")
			}
			stack[len(stack)-1].key = true
		}
		return nil
	}
	for tokens := 0; ; tokens++ {
		token, err := decoder.Token()
		if err == io.EOF {
			if len(stack) != 0 {
				return io.ErrUnexpectedEOF
			}
			return nil
		}
		if err != nil {
			return err
		}
		if tokens >= MaxJSONTokens {
			return errors.New("JSON exceeds the 100000-token work limit")
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				if err := value(); err != nil {
					return err
				}
				if len(stack) >= MaxJSONDepth {
					return errors.New("JSON exceeds the 64-level nesting limit")
				}
				stack = append(stack, jsonFrame{object: delimiter == '{', key: delimiter == '{'})
			case '}', ']':
				if len(stack) == 0 {
					return errors.New("unexpected JSON closing delimiter")
				}
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].key {
			key, ok := token.(string)
			if !ok {
				return errors.New("JSON object member name must be a string")
			}
			if len(key) > MaxJSONKeyBytes {
				return errors.New("JSON member name exceeds the 256-byte limit")
			}
			stack[len(stack)-1].key = false
			continue
		}
		switch token := token.(type) {
		case string:
			if len(token) > MaxJSONTokenBytes {
				return errors.New("JSON string exceeds the 64 KiB token limit")
			}
		case json.Number:
			if len(token) > MaxJSONTokenBytes {
				return errors.New("JSON number exceeds the 64 KiB token limit")
			}
		}
		if err := value(); err != nil {
			return err
		}
	}
}
