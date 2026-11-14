package guardian

import (
	"encoding"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
)

// Match the evaluate route's argument depth, node and body-size ceilings.
// Native adapters have no HTTP decoder bound, so Guardian enforces these too.
const (
	threatInputMaxDepth = 64
	threatInputMaxNodes = 4096
	threatInputMaxBytes = 1 << 20
)

// collectThreatInputs keeps text leaves separate: joining unrelated arguments
// can manufacture a threat phrase that the caller never supplied. Fixed field
// order, sorted object keys and array order make the first literal denial stable.
// An incomplete walk is an error, never evidence of a clean scan.
func collectThreatInputs(input map[string]any) ([]string, error) {
	walk := threatInputWalk{}
	for _, key := range []string{"user_input", "text", "content"} {
		if text, ok := input[key].(string); ok {
			if err := walk.addText(text); err != nil {
				return nil, err
			}
		}
	}
	if args, exists := input["args"]; exists {
		if err := walk.visit(reflect.ValueOf(args), 0); err != nil {
			return nil, err
		}
	}
	return walk.texts, nil
}

type threatInputWalk struct {
	texts []string
	nodes int
	bytes int
}

func (w *threatInputWalk) chargeBytes(size int) error {
	if size > threatInputMaxBytes-w.bytes {
		return fmt.Errorf("text and object keys exceed %d bytes", threatInputMaxBytes)
	}
	w.bytes += size
	return nil
}

func (w *threatInputWalk) addText(text string) error {
	if err := w.chargeBytes(len(text)); err != nil {
		return err
	}
	if text != "" {
		w.texts = append(w.texts, text)
	}
	return nil
}

func (w *threatInputWalk) visit(value reflect.Value, depth int) error {
	w.nodes++
	if w.nodes > threatInputMaxNodes {
		return fmt.Errorf("arguments exceed %d nodes", threatInputMaxNodes)
	}
	for value.IsValid() && value.Kind() == reflect.Interface {
		value = value.Elem()
	}
	if !value.IsValid() {
		return nil
	}
	// Custom JSON or text methods can hide a different wire value. encoding/json
	// also invokes pointer methods on addressable elements. Reject these types
	// without calling their methods; adapters must supply decoded JSON values.
	jsonMarshaler := reflect.TypeFor[json.Marshaler]()
	textMarshaler := reflect.TypeFor[encoding.TextMarshaler]()
	valueType := value.Type()
	if valueType.Implements(jsonMarshaler) || valueType.Implements(textMarshaler) ||
		(value.CanAddr() && (value.Addr().Type().Implements(jsonMarshaler) || value.Addr().Type().Implements(textMarshaler))) {
		return fmt.Errorf("arguments require decoded JSON values")
	}
	switch value.Kind() {
	case reflect.String:
		// json.Number has a string representation but encodes as a number.
		// Bound validation work and require a finite, syntactically valid value.
		if number, ok := value.Interface().(json.Number); ok {
			if err := w.chargeBytes(len(number)); err != nil {
				return err
			}
			parsed, err := number.Float64()
			if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || !json.Valid([]byte(number)) {
				return fmt.Errorf("arguments require finite JSON numbers")
			}
			return nil
		}
		return w.addText(value.String())
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return nil
	case reflect.Float32, reflect.Float64:
		if number := value.Float(); math.IsNaN(number) || math.IsInf(number, 0) {
			return fmt.Errorf("arguments require finite JSON numbers")
		}
		return nil
	case reflect.Map, reflect.Slice, reflect.Array:
		if depth >= threatInputMaxDepth {
			return fmt.Errorf("arguments exceed %d container levels", threatInputMaxDepth)
		}
		if value.Len() > threatInputMaxNodes-w.nodes {
			return fmt.Errorf("arguments exceed %d nodes", threatInputMaxNodes)
		}
		if value.Kind() == reflect.Map {
			if value.Type().Key().Kind() != reflect.String {
				return fmt.Errorf("argument object keys must be strings")
			}
			keys := value.MapKeys()
			for _, key := range keys {
				if err := w.chargeBytes(len(key.String())); err != nil {
					return err
				}
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
			for _, key := range keys {
				if err := w.visit(value.MapIndex(key), depth+1); err != nil {
					return err
				}
			}
			return nil
		}
		// encoding/json turns []byte into base64, not a JSON array. Do not
		// silently treat that opaque payload as inspected text.
		if value.Kind() == reflect.Slice && value.Type().Elem().Kind() == reflect.Uint8 {
			return fmt.Errorf("arguments require decoded JSON values")
		}
		for i := 0; i < value.Len(); i++ {
			if err := w.visit(value.Index(i), depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("arguments require JSON objects, arrays or scalars")
	}
}
