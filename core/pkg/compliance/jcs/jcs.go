package jcs

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
)

// Marshal serializes the value to JSON using JCS principles (sorted keys).
// Go's encoding/json sorts maps by key by default, satisfying the main requirement.
// We add validation for NaNs/Infs which are not valid JSON but Go allows marshaling to null or error.
func Marshal(v any) ([]byte, error) {
	if hasNaNOrInf(reflect.ValueOf(v)) {
		return nil, fmt.Errorf("JCS validation failed: value contains NaN or Infinity")
	}
	return json.Marshal(v)
}

//nolint:gocognit // complexity acceptable
func hasNaNOrInf(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		return math.IsNaN(f) || math.IsInf(f, 0)
	case reflect.Map:
		for _, key := range v.MapKeys() {
			if hasNaNOrInf(v.MapIndex(key)) {
				return true
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if hasNaNOrInf(v.Index(i)) {
				return true
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if hasNaNOrInf(v.Field(i)) {
				return true
			}
		}
	case reflect.Ptr, reflect.Interface:
		if !v.IsNil() {
			return hasNaNOrInf(v.Elem())
		}
	}
	return false
}
