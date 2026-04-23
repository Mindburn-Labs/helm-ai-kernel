package canonicalize

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFinal_JCSNil(t *testing.T) {
	data, err := JCS(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "null" {
		t.Fatalf("expected null, got %s", data)
	}
}

func TestFinal_JCSBool(t *testing.T) {
	data, _ := JCS(true)
	if string(data) != "true" {
		t.Fatal("bool mismatch")
	}
}

func TestFinal_JCSString(t *testing.T) {
	data, _ := JCS("hello")
	if string(data) != `"hello"` {
		t.Fatalf("string mismatch: %s", data)
	}
}

func TestFinal_JCSNumber(t *testing.T) {
	data, _ := JCS(42)
	if string(data) != "42" {
		t.Fatalf("number mismatch: %s", data)
	}
}

func TestFinal_JCSArray(t *testing.T) {
	data, _ := JCS([]int{1, 2, 3})
	if string(data) != "[1,2,3]" {
		t.Fatalf("array mismatch: %s", data)
	}
}

func TestFinal_JCSKeySorting(t *testing.T) {
	m := map[string]interface{}{"z": 1, "a": 2}
	data, _ := JCS(m)
	s := string(data)
	aIdx := strings.Index(s, `"a"`)
	zIdx := strings.Index(s, `"z"`)
	if aIdx >= zIdx {
		t.Fatal("keys not sorted")
	}
}

func TestFinal_JCSDeterministic(t *testing.T) {
	m := map[string]interface{}{"b": 1, "a": 2}
	d1, _ := JCS(m)
	d2, _ := JCS(m)
	if string(d1) != string(d2) {
		t.Fatal("not deterministic")
	}
}

func TestFinal_JCSStruct(t *testing.T) {
	type S struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	data, err := JCS(S{Name: "test", Age: 30})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"name"`) {
		t.Fatal("struct fields missing")
	}
}

func TestFinal_JCSNoHTMLEscaping(t *testing.T) {
	data, _ := JCS(map[string]interface{}{"url": "http://example.com?a=1&b=2"})
	if strings.Contains(string(data), `\u0026`) {
		t.Fatal("HTML escaping should be disabled")
	}
}

func TestFinal_CanonicalHash(t *testing.T) {
	h, err := CanonicalHash(map[string]interface{}{"key": "val"})
	if err != nil || h == "" {
		t.Fatal("canonical hash failed")
	}
}

func TestFinal_CanonicalHashDeterministic(t *testing.T) {
	m := map[string]interface{}{"z": 1, "a": 2}
	h1, _ := CanonicalHash(m)
	h2, _ := CanonicalHash(m)
	if h1 != h2 {
		t.Fatal("not deterministic")
	}
}

func TestFinal_CanonicalHashDifferentInputs(t *testing.T) {
	h1, _ := CanonicalHash(map[string]interface{}{"a": 1})
	h2, _ := CanonicalHash(map[string]interface{}{"a": 2})
	if h1 == h2 {
		t.Fatal("different inputs should have different hashes")
	}
}

func TestFinal_HashBytes(t *testing.T) {
	h := HashBytes([]byte("test"))
	if len(h) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h))
	}
}

func TestFinal_HashBytesDeterministic(t *testing.T) {
	h1 := HashBytes([]byte("data"))
	h2 := HashBytes([]byte("data"))
	if h1 != h2 {
		t.Fatal("not deterministic")
	}
}

func TestFinal_JCSStringReturn(t *testing.T) {
	s, err := JCSString(map[string]interface{}{"k": "v"})
	if err != nil || s == "" {
		t.Fatal("JCSString failed")
	}
}

func TestFinal_CanonicalizePlainText(t *testing.T) {
	a, err := Canonicalize("text-schema", "hello world")
	if err != nil {
		t.Fatal(err)
	}
	if a.ContentType != "text/plain" {
		t.Fatal("expected text/plain")
	}
}

func TestFinal_CanonicalizeBytes(t *testing.T) {
	a, err := Canonicalize("bin-schema", []byte{0x01, 0x02})
	if err != nil {
		t.Fatal(err)
	}
	if a.ContentType != "application/octet-stream" {
		t.Fatal("expected application/octet-stream")
	}
}

func TestFinal_CanonicalizeJSON(t *testing.T) {
	a, err := Canonicalize("json-schema", map[string]interface{}{"key": "val"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ContentType != "application/json" {
		t.Fatal("expected application/json")
	}
}

func TestFinal_CanonicalizeDigestPrefix(t *testing.T) {
	a, _ := Canonicalize("s", "test")
	if !strings.HasPrefix(a.Digest, "sha256:") {
		t.Fatal("missing sha256 prefix")
	}
}

func TestFinal_CanonicalizeDigestDeterministic(t *testing.T) {
	a1, _ := Canonicalize("s", "same input")
	a2, _ := Canonicalize("s", "same input")
	if a1.Digest != a2.Digest {
		t.Fatal("not deterministic")
	}
}

func TestFinal_CanonicalizePreview(t *testing.T) {
	a, _ := Canonicalize("s", "short")
	if a.Preview != "short" {
		t.Fatal("preview should equal short content")
	}
}

func TestFinal_CanonicalizePreviewTruncated(t *testing.T) {
	long := strings.Repeat("x", 100)
	a, _ := Canonicalize("s", long)
	if len(a.Preview) > 60 {
		t.Fatal("preview should be truncated")
	}
}

func TestFinal_CanonicalizeSchemaID(t *testing.T) {
	a, _ := Canonicalize("my-schema", "data")
	if a.SchemaID != "my-schema" {
		t.Fatal("schema ID should be preserved")
	}
}

func TestFinal_CanonicalizeMetadataInit(t *testing.T) {
	a, _ := Canonicalize("s", "data")
	if a.Metadata == nil {
		t.Fatal("metadata should be initialized")
	}
}

func TestFinal_ComputeArtifactHash(t *testing.T) {
	h := ComputeArtifactHash([]byte("test"))
	if !strings.HasPrefix(h, "sha256:") {
		t.Fatal("missing prefix")
	}
}

func TestFinal_ComputeArtifactHashDeterministic(t *testing.T) {
	h1 := ComputeArtifactHash([]byte("data"))
	h2 := ComputeArtifactHash([]byte("data"))
	if h1 != h2 {
		t.Fatal("not deterministic")
	}
}

func TestFinal_JCSNestedObjects(t *testing.T) {
	m := map[string]interface{}{
		"outer": map[string]interface{}{
			"b": 2,
			"a": 1,
		},
	}
	data, _ := JCS(m)
	s := string(data)
	aIdx := strings.Index(s, `"a"`)
	bIdx := strings.Index(s, `"b"`)
	if aIdx >= bIdx {
		t.Fatal("nested keys not sorted")
	}
}

func TestFinal_JCSEmptyMap(t *testing.T) {
	data, _ := JCS(map[string]interface{}{})
	if string(data) != "{}" {
		t.Fatalf("expected {}, got %s", data)
	}
}

func TestFinal_JCSEmptyArray(t *testing.T) {
	data, _ := JCS([]interface{}{})
	if string(data) != "[]" {
		t.Fatalf("expected [], got %s", data)
	}
}

func TestFinal_JCSJsonNumber(t *testing.T) {
	m := map[string]interface{}{"n": json.Number("3.14")}
	data, _ := JCS(m)
	if !strings.Contains(string(data), "3.14") {
		t.Fatal("json.Number not preserved")
	}
}

func TestFinal_GeneratePreviewShort(t *testing.T) {
	p := generatePreview([]byte("hi"))
	if p != "hi" {
		t.Fatal("short preview")
	}
}

func TestFinal_GeneratePreviewLong(t *testing.T) {
	p := generatePreview([]byte(strings.Repeat("a", 100)))
	if !strings.HasSuffix(p, "...") {
		t.Fatal("long preview should end with ...")
	}
}
