package csnf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"golang.org/x/text/unicode/norm"
)

// Canonicalize transforms an artifact into CSNF form.
func Canonicalize(artifact interface{}) (interface{}, error) {
	val := reflect.ValueOf(artifact)

	switch val.Kind() {
	case reflect.Map:
		// Maps become sorted by key (encoding/json does this, but we need to recurse)
		out := make(map[string]interface{})
		iter := val.MapRange()
		for iter.Next() {
			k := iter.Key().String()
			v := iter.Value().Interface()

			// Recurse
			canV, err := Canonicalize(v)
			if err != nil {
				return nil, err
			}

			// Null stripping rule: if value is nil, omit it?
			// Spec says: "CSNF canonicalization MUST remove any null value for fields not marked nullable."
			// For MVP, we assume rigid adherence and strip all nulls for simplicity unless schema awareness is added.
			if canV == nil {
				continue
			}
			out[k] = canV
		}
		return out, nil

	case reflect.Slice, reflect.Array:
		out := make([]interface{}, val.Len())
		for i := 0; i < val.Len(); i++ {
			elem := val.Index(i).Interface()
			canElem, err := Canonicalize(elem)
			if err != nil {
				return nil, err
			}
			out[i] = canElem
		}
		// NOTE: SET sorting requires schema awareness (§6.3 Tier 2). In v0.1, arrays are treated as ordered
		// sequences. Callers must ensure deterministic input ordering for set-typed collections.
		return out, nil

	case reflect.String:
		// NFC Normalization
		s := val.String()
		return norm.NFC.String(s), nil

	case reflect.Float64, reflect.Float32:
		// Reject floats
		// check if it's an integer
		f := val.Float()
		if f != float64(int64(f)) {
			return nil, errors.New("CSNF: fractional numbers not allowed")
		}
		return int64(f), nil // Convert to int

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return val.Int(), nil

	case reflect.Bool:
		return val.Bool(), nil

	case reflect.Invalid: // nil
		return nil, nil // Return nil, caller handles stripping

	default:
		return nil, fmt.Errorf("CSNF: unsupported type %T", artifact)
	}
}

// Hash computes the SHA256 hash of the canonicalized artifact.
func Hash(artifact interface{}) (string, error) {
	// 1. Canonicalize
	can, err := Canonicalize(artifact)
	if err != nil {
		return "", err
	}
	if can == nil {
		// Empty hash? Or error?
		return "", errors.New("canonicalization resulted in nil")
	}

	// 2. JCS (JSON Canonicalization Scheme)
	// encoding/json produces sorted keys, which is compatible with JCS for simple maps.
	// It does NOT handle some JCS edge cases like float formatting (which we rejected anyway).
	bytes, err := json.Marshal(can)
	if err != nil {
		return "", err
	}

	// 3. Hash
	h := sha256.Sum256(bytes)
	return hex.EncodeToString(h[:]), nil
}
