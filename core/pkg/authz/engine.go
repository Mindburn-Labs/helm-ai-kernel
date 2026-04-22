package authz

import (
	"context"
	"fmt"
	"sync"
)

// RelationTuple represents a directed edge in the relationship graph.
// (User:alice) -> [viewer] -> (Doc:readme)
type RelationTuple struct {
	Object   string `json:"object"`   // namespace:id (e.g., "doc:readme")
	Relation string `json:"relation"` // e.g., "viewer", "editor", "owner"
	Subject  string `json:"subject"`  // User or Set (e.g., "user:alice", "group:devs#member")
}

// Engine implements the Relationship-Based Access Control (ReBAC) system.
type Engine struct {
	mu     sync.RWMutex
	graph  map[string]struct{} // Set of "object#relation@subject" strings for fast lookup
	tuples []RelationTuple
}

func NewEngine() *Engine {
	return &Engine{
		graph:  make(map[string]struct{}),
		tuples: make([]RelationTuple, 0),
	}
}

// WriteTuple adds a relationship to the graph.
func (e *Engine) WriteTuple(ctx context.Context, tuple RelationTuple) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := e.tupleKey(tuple)
	if _, exists := e.graph[key]; exists {
		return nil // Idempotent
	}

	e.graph[key] = struct{}{}
	e.tuples = append(e.tuples, tuple)
	return nil
}

// Check verifies if "subject" has "relation" on "object".
// Returns true if the relationship exists directly or transitively.
func (e *Engine) Check(ctx context.Context, object, relation, subject string) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.checkRecursive(object, relation, subject, make(map[string]bool))
}

func (e *Engine) checkRecursive(object, relation, subject string, visited map[string]bool) (bool, error) {
	// 1. Direct Check
	// Does object#relation@subject exist?
	targetKey := fmt.Sprintf("%s#%s@%s", object, relation, subject)
	if _, ok := e.graph[targetKey]; ok {
		return true, nil
	}

	// 2. Loop detection
	visitKey := fmt.Sprintf("%s#%s", object, relation)
	if visited[visitKey] {
		return false, nil // Cycle detected or already visited this node
	}
	visited[visitKey] = true

	// 3. Indirect / Expansion (simplified)
	// Iterate through all tuples to find:
	// a) Group membership: (object#relation@group:G) AND (group:G#member@subject)
	// b) Relation rewrite: (object#owner@subject) IMPLIES (object#viewer@subject)

	for _, t := range e.tuples {
		// Matching Object?
		if t.Object != object {
			continue
		}

		// Rewrite: if I am checking for 'viewer', maybe 'owner' also grants it?
		// (This requires a schema, for MVP we hardcode specific implicits or stick to direct graph traversal)
		// For MVP: We only support direct group expansion.

		// If t.Relation == relation
		if t.Relation == relation {
			// Check if t.Subject is a SubjectSet (e.g. group:admins#member)
			// If t.Subject matches the requested subject, we would have found it in step 1.
			// So t.Subject is likely an intermediate group.
			// Recursively check if 'subject' is a member of 't.Subject'.

			// If t.Subject is "group:admins", we check if subject has relation "member" on "group:admins"
			// But t.Subject format in Zanzibar is typically "group:admins#member"

			// Parse t.Subject
			// If it's a simple user ID, it didn't match step 1, so it's a diff user.
			// If it's a set...
			// Let's support simple groups: subject = "group:x".
			// Recursively check: Check("group:x", "member", subject)

			if isGroup(t.Subject) {
				isMember, _ := e.checkRecursive(t.Subject, "member", subject, visited)
				if isMember {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func (e *Engine) tupleKey(t RelationTuple) string {
	return fmt.Sprintf("%s#%s@%s", t.Object, t.Relation, t.Subject)
}

func isGroup(subject string) bool {
	// Simple heuristic for MVP
	return len(subject) > 6 && subject[:6] == "group:"
}
