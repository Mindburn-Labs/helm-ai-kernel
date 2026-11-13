// quantum_posture: member-name matching adds no signature scheme or trusted
// root.
package receiptverify

import (
	"encoding"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"unicode"
)

// foldName returns the one spelling every letter-case variant of a member name
// shares under Unicode simple case folding: each rune becomes the smallest
// rune of its fold orbit.
//
// encoding/json binds an object member to a struct field when the two names
// are equal under this folding, so the Kelvin sign and the long s bind to
// fields named with k and s. A reader that matches names exactly (jq, a
// JavaScript host) sees those as different members. The scan therefore treats
// two names with one folded form as one name: accepting both would let a
// document say one thing to this verifier and another to its reader.
func foldName(name string) string {
	return strings.Map(func(r rune) rune {
		for {
			next := unicode.SimpleFold(r)
			if next <= r {
				return next
			}
			r = next
		}
	}, name)
}

// memberSet is the member names encoding/json binds for one struct type.
type memberSet struct {
	// exact maps a member name to the type its value is decoded into.
	exact map[string]reflect.Type
	// folded maps the folded form of each name back to its exact spelling.
	folded map[string]string
}

var (
	jsonUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()

	memberSets sync.Map // reflect.Type (struct) to *memberSet
)

// decodeTarget reduces the type a JSON value is decoded into to the part that
// gives its nested member names a meaning: a struct, or a map, slice or array
// that may hold one. It returns nil for everything whose content is data to
// encoding/json: scalars, interface values, and types that decode themselves
// (json.RawMessage, time.Time).
func decodeTarget(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil {
		return nil
	}
	if pointer := reflect.PointerTo(t); pointer.Implements(jsonUnmarshalerType) || pointer.Implements(textUnmarshalerType) {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct, reflect.Map, reflect.Slice, reflect.Array:
		return t
	default:
		return nil
	}
}

// membersOf derives a struct type's member names the way encoding/json does:
// the json tag's name, or the field's name when the tag has none or an
// invalid one; "-" and unexported fields are skipped; the fields of an
// untagged embedded struct are promoted, an outer field winning over a
// promoted one of the same name.
//
// The names are read from the types themselves so that a field added to a
// receipt, permit, bundle or binding is covered here with no second list.
func membersOf(t reflect.Type) *memberSet {
	if cached, ok := memberSets.Load(t); ok {
		return cached.(*memberSet)
	}
	set := &memberSet{exact: map[string]reflect.Type{}, folded: map[string]string{}}
	var promoted []reflect.Type
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		embedded := embeddedStruct(field)
		// An unexported field is invisible to encoding/json unless it embeds
		// a struct, whose exported fields are still reachable.
		if !field.IsExported() && embedded == nil {
			continue
		}
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if !validTagName(name) {
			name = ""
		}
		if name == "" && embedded != nil {
			promoted = append(promoted, embedded)
			continue
		}
		if name == "" {
			name = field.Name
		}
		set.exact[name] = field.Type
	}
	for _, embedded := range promoted {
		for name, fieldType := range membersOf(embedded).exact {
			if _, outer := set.exact[name]; !outer {
				set.exact[name] = fieldType
			}
		}
	}
	for name := range set.exact {
		set.folded[foldName(name)] = name
	}
	actual, _ := memberSets.LoadOrStore(t, set)
	return actual.(*memberSet)
}

// embeddedStruct returns the struct type an anonymous field embeds, directly
// or through a pointer, or nil.
func embeddedStruct(field reflect.StructField) reflect.Type {
	if !field.Anonymous {
		return nil
	}
	t := field.Type
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	return t
}

// validTagName reports whether encoding/json honours name as a json tag name.
// It ignores a tag name holding anything but letters, digits and the
// punctuation below, and falls back to the field's name.
func validTagName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if !strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", c) && !unicode.IsLetter(c) && !unicode.IsDigit(c) {
			return false
		}
	}
	return true
}
