package authz_test

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/authz"
	"github.com/stretchr/testify/assert"
)

func TestAuthZ_Engine(t *testing.T) {
	engine := authz.NewEngine()
	ctx := context.Background()

	// 1. Direct Relation
	// alice is viewer of doc:readme
	engine.WriteTuple(ctx, authz.RelationTuple{
		Object:   "doc:readme",
		Relation: "viewer",
		Subject:  "user:alice",
	})

	allowed, _ := engine.Check(ctx, "doc:readme", "viewer", "user:alice")
	assert.True(t, allowed, "Alice should be viewer")

	allowed, _ = engine.Check(ctx, "doc:readme", "editor", "user:alice")
	assert.False(t, allowed, "Alice should NOT be editor")

	// 2. Group Membership (Recursive)
	// bob is member of group:devs
	engine.WriteTuple(ctx, authz.RelationTuple{
		Object:   "group:devs",
		Relation: "member",
		Subject:  "user:bob",
	})
	// group:devs is editor of doc:code
	engine.WriteTuple(ctx, authz.RelationTuple{
		Object:   "doc:code",
		Relation: "editor",
		Subject:  "group:devs",
	})

	// Check if bob is editor of doc:code (via group:devs)
	allowed, _ = engine.Check(ctx, "doc:code", "editor", "user:bob")
	assert.True(t, allowed, "Bob should be editor via group:devs")
}
