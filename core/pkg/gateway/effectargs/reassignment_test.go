package effectargs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

func grantObject() map[string]any {
	return map[string]any{
		"schema":          WorkReassignmentManifest,
		"reassignment_id": "11111111-1111-7111-8111-111111111111",
		"drain_digest":    "sha256:" + strings.Repeat("a", 64),
		"org_ref":         "org:one", "work_item_id": "work:one", "organization_version_id": "version:one",
		"commitment_id": "commitment:one", "terms_digest": "sha256:" + strings.Repeat("b", 64),
		"plan_digest": strings.Repeat("c", 64), "authority_revision": 2,
		"expected_generation": 0, "generation": 1,
		"expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		"recipient": map[string]any{"episode_id": "episode:new", "seat_id": "new", "principal_id": "agt:new",
			"actor_id": "cp:gateway", "profile": "executor", "client": "codex"},
		"sources": []any{map[string]any{"episode_id": "episode:old", "seat_id": "old", "principal_id": "agt:old",
			"actor_id": "cp:gateway", "profile": "executor", "attempt_ids": []string{"22222222-2222-7222-8222-222222222222"}}},
	}
}

func encodeGrant(t *testing.T, object map[string]any) []byte {
	t.Helper()
	delete(object, "manifest_digest")
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalize.JCS(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	object["manifest_digest"] = "sha256:" + hex.EncodeToString(sum[:])
	raw, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWorkReassignmentGrantClosedAndBound(t *testing.T) {
	valid := encodeGrant(t, grantObject())
	grant, err := ParseWorkReassignmentGrant(valid)
	if err != nil || grant.Recipient.PrincipalID != "agt:new" {
		t.Fatalf("valid grant = %+v, %v", grant, err)
	}
	if _, err := Validate(AuthorityWorkReassignmentGrant, "org:one", valid); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(AuthorityWorkReassignmentGrant, "org:two", valid); err == nil {
		t.Fatal("a different target was accepted")
	}
	for name, mutate := range map[string]func(map[string]any){
		"foreign principal": func(m map[string]any) { m["recipient"].(map[string]any)["principal_id"] = "agt:old" },
		"cross profile":     func(m map[string]any) { m["recipient"].(map[string]any)["profile"] = "worker" },
		"generation gap":    func(m map[string]any) { m["generation"] = 3 },
		"unknown field":     func(m map[string]any) { m["unexpected"] = true },
		"nested alias":      func(m map[string]any) { m["recipient"].(map[string]any)["Seat_ID"] = "new" },
		"duplicate member": func(m map[string]any) {
			m["sources"].([]any)[0].(map[string]any)["attempt_ids"] = []string{
				"22222222-2222-7222-8222-222222222222", "22222222-2222-7222-8222-222222222222"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			object := grantObject()
			mutate(object)
			if _, err := ParseWorkReassignmentGrant(encodeGrant(t, object)); err == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
	object := grantObject()
	badDigest := encodeGrant(t, object)
	var tampered map[string]any
	if err := json.Unmarshal(badDigest, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered["work_item_id"] = "work:other"
	raw, _ := json.Marshal(tampered)
	if _, err := ParseWorkReassignmentGrant(raw); err == nil {
		t.Fatal("a manifest whose digest binds another work item was accepted")
	}
	if _, err := ParseWorkReassignmentGrant(append(valid[:len(valid)-1], []byte(`,"schema":"helm.work-reassignment.v1"}`)...)); err == nil {
		t.Fatal("duplicate schema key accepted")
	}
}

func TestWorkReassignmentEmptyDrainHasNoHistoricalActorOrMembers(t *testing.T) {
	object := grantObject()
	source := object["sources"].([]any)[0].(map[string]any)
	source["attempt_ids"] = []string{}
	source["actor_id"] = ""
	if _, err := ParseWorkReassignmentGrant(encodeGrant(t, object)); err != nil {
		t.Fatalf("closed zero-member drain: %v", err)
	}
	source["attempt_ids"] = []string{"22222222-2222-7222-8222-222222222222"}
	if _, err := ParseWorkReassignmentGrant(encodeGrant(t, object)); err == nil {
		t.Fatal("a real native attempt was accepted without its original actor")
	}
}

func TestWorkReassignmentPredecessorIsClosedAndDigestBound(t *testing.T) {
	object := grantObject()
	object["predecessor_reassignment_id"] = "33333333-3333-7333-8333-333333333333"
	raw := encodeGrant(t, object)
	parsed, err := ParseWorkReassignmentGrant(raw)
	if err != nil || parsed.PredecessorReassignmentID != object["predecessor_reassignment_id"] {
		t.Fatalf("exact predecessor was lost: %+v %v", parsed, err)
	}
	var changed map[string]any
	if err := json.Unmarshal(raw, &changed); err != nil {
		t.Fatal(err)
	}
	delete(changed, "predecessor_reassignment_id")
	tampered, _ := json.Marshal(changed)
	if _, err := ParseWorkReassignmentGrant(tampered); err == nil {
		t.Fatal("removing a predecessor did not invalidate the manifest digest")
	}
	object["predecessor_reassignment_id"] = ""
	if _, err := ParseWorkReassignmentGrant(encodeGrant(t, object)); err == nil {
		t.Fatal("an empty predecessor was accepted")
	}
}
