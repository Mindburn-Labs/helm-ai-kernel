package receiptverify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type sdkMemberShape struct {
	Fields  map[string]*sdkMemberShape `json:"fields,omitempty"`
	Element *sdkMemberShape            `json:"element,omitempty"`
	Kind    string                     `json:"kind,omitempty"`
}

func sdkShape(t reflect.Type) *sdkMemberShape {
	t = decodeTarget(t)
	if t == nil {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		shape := &sdkMemberShape{Kind: "object", Fields: map[string]*sdkMemberShape{}}
		for name, target := range membersOf(t).exact {
			shape.Fields[name] = sdkShape(target)
		}
		return shape
	case reflect.Array, reflect.Slice:
		if elem := sdkShape(t.Elem()); elem != nil {
			return &sdkMemberShape{Kind: "array", Element: elem}
		}
	case reflect.Map:
		if elem := sdkShape(t.Elem()); elem != nil {
			return &sdkMemberShape{Kind: "map", Element: elem}
		}
	}
	return nil
}

// If the owning receipt type grows, SDK parser shadow protection must grow
// with it. Free-form maps remain data and preserve case-sensitive keys.
func TestSDKReceiptMemberNamesMatchOwningParser(t *testing.T) {
	expected, err := json.Marshal(sdkShape(reflect.TypeFor[contracts.Receipt]()))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join(sdkVectorRoot(), "core/pkg/receiptverify/testdata/offline-receipt-members.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(fixture), expected) {
		t.Fatal("SDK member shape no longer matches contracts.Receipt")
	}
	for _, language := range []struct {
		path   string
		quoted bool
	}{
		{"sdk/go/client/verify_members.go", false},
		{"sdk/python/helm_sdk/verify_members.py", false},
		{"sdk/ts/src/verify-members.ts", true},
	} {
		source, err := os.ReadFile(filepath.Join(sdkVectorRoot(), language.path))
		if err != nil {
			t.Fatal(err)
		}
		needle := string(expected)
		if language.quoted {
			needle = strconv.Quote(needle)
		}
		if !strings.Contains(string(source), needle) {
			t.Errorf("%s does not embed the pinned receipt member shape", language.path)
		}
	}
}

func TestSDKOfflineVectorSourcesUnchanged(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(sdkVectorRoot(), "core/pkg/receiptverify/testdata/offline-verifier-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Sources map[string]string `json:"sources"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Sources) == 0 {
		t.Fatal("SDK corpus has no owning source identities")
	}
	for path, want := range corpus.Sources {
		raw, err := os.ReadFile(filepath.Join(sdkVectorRoot(), path))
		if err != nil {
			t.Fatal(err)
		}
		got := sha256.Sum256(raw)
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("%s changed: requalify shared signed vectors", path)
		}
	}
}

func sdkVectorRoot() string {
	if root := os.Getenv("HELM_SDK_VECTOR_ROOT"); root != "" {
		return root
	}
	return "../../.."
}
