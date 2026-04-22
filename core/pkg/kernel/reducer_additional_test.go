package kernel

import (
	"context"
	"testing"
)

//nolint:gocognit // test complexity is acceptable
func TestDeterministicReducer(t *testing.T) {
	t.Run("Basic reduce", func(t *testing.T) {
		reducer := NewDeterministicReducer(ConflictPolicyFirstSuccess)

		inputs := []ReducerInput{
			{SequenceNumber: 1, Key: "key1", Value: "value1", SortKey: "a"},
			{SequenceNumber: 2, Key: "key2", Value: "value2", SortKey: "b"},
		}

		output, err := reducer.Reduce(context.Background(), inputs)
		if err != nil {
			t.Fatalf("Reduce failed: %v", err)
		}

		if len(output.State) != 2 {
			t.Errorf("State length = %d, want 2", len(output.State))
		}
		if output.State["key1"] != "value1" {
			t.Error("key1 should have value1")
		}
		if output.StateHash == "" {
			t.Error("StateHash should be set")
		}
	})

	t.Run("Policy", func(t *testing.T) {
		reducer := NewDeterministicReducer(ConflictPolicyLastWriteWins)
		if reducer.Policy() != ConflictPolicyLastWriteWins {
			t.Error("Policy should return correct policy")
		}
	})

	t.Run("Conflict FirstSuccess", func(t *testing.T) {
		reducer := NewDeterministicReducer(ConflictPolicyFirstSuccess)

		inputs := []ReducerInput{
			{SequenceNumber: 1, Key: "key1", Value: "first", SortKey: "a"},
			{SequenceNumber: 2, Key: "key1", Value: "second", SortKey: "b"},
		}

		output, err := reducer.Reduce(context.Background(), inputs)
		if err != nil {
			t.Fatalf("Reduce failed: %v", err)
		}

		if output.State["key1"] != "first" {
			t.Errorf("FirstSuccess policy: State = %v, want 'first'", output.State["key1"])
		}
		if len(output.Conflicts) != 1 {
			t.Errorf("Should have 1 conflict, got %d", len(output.Conflicts))
		}
	})

	t.Run("Conflict LastWriteWins", func(t *testing.T) {
		reducer := NewDeterministicReducer(ConflictPolicyLastWriteWins)

		inputs := []ReducerInput{
			{SequenceNumber: 1, Key: "key1", Value: "first", SortKey: "a"},
			{SequenceNumber: 2, Key: "key1", Value: "second", SortKey: "b"},
		}

		output, err := reducer.Reduce(context.Background(), inputs)
		if err != nil {
			t.Fatalf("Reduce failed: %v", err)
		}

		if output.State["key1"] != "second" {
			t.Errorf("LastWriteWins policy: State = %v, want 'second'", output.State["key1"])
		}
	})

	t.Run("Conflict VerifierWins higher seq wins", func(t *testing.T) {
		reducer := NewDeterministicReducer(ConflictPolicyVerifierWins)

		inputs := []ReducerInput{
			{SequenceNumber: 1, Key: "key1", Value: "first", SortKey: "a"},
			{SequenceNumber: 2, Key: "key1", Value: "second", SortKey: "b"},
		}

		output, err := reducer.Reduce(context.Background(), inputs)
		if err != nil {
			t.Fatalf("Reduce failed: %v", err)
		}

		// Higher sequence number wins
		if output.State["key1"] != "second" {
			t.Errorf("VerifierWins policy: State = %v, want 'second'", output.State["key1"])
		}
	})

	t.Run("Conflict VerifierWins lower seq loses", func(t *testing.T) {
		reducer := NewDeterministicReducer(ConflictPolicyVerifierWins)

		// Higher sortKey but lower sequence number
		inputs := []ReducerInput{
			{SequenceNumber: 10, Key: "key1", Value: "high-seq", SortKey: "a"},
			{SequenceNumber: 5, Key: "key1", Value: "low-seq", SortKey: "b"},
		}

		output, err := reducer.Reduce(context.Background(), inputs)
		if err != nil {
			t.Fatalf("Reduce failed: %v", err)
		}

		// Higher sequence number should win
		if output.State["key1"] != "high-seq" {
			t.Errorf("VerifierWins policy: State = %v, want 'high-seq'", output.State["key1"])
		}
	})

	t.Run("Default policy", func(t *testing.T) {
		reducer := NewDeterministicReducer("unknown_policy")

		inputs := []ReducerInput{
			{SequenceNumber: 1, Key: "key1", Value: "first", SortKey: "a"},
			{SequenceNumber: 2, Key: "key1", Value: "second", SortKey: "b"},
		}

		output, err := reducer.Reduce(context.Background(), inputs)
		if err != nil {
			t.Fatalf("Reduce failed: %v", err)
		}

		// Default should behave like FirstSuccess
		if output.State["key1"] != "first" {
			t.Errorf("Default policy: State = %v, want 'first'", output.State["key1"])
		}
	})

	t.Run("Sort order determinism", func(t *testing.T) {
		reducer := NewDeterministicReducer(ConflictPolicyFirstSuccess)

		// Different input orders should produce same result
		inputs1 := []ReducerInput{
			{SequenceNumber: 3, Key: "c", Value: "3", SortKey: "c"},
			{SequenceNumber: 1, Key: "a", Value: "1", SortKey: "a"},
			{SequenceNumber: 2, Key: "b", Value: "2", SortKey: "b"},
		}

		output1, _ := reducer.Reduce(context.Background(), inputs1)

		reducer2 := NewDeterministicReducer(ConflictPolicyFirstSuccess)
		inputs2 := []ReducerInput{
			{SequenceNumber: 1, Key: "a", Value: "1", SortKey: "a"},
			{SequenceNumber: 2, Key: "b", Value: "2", SortKey: "b"},
			{SequenceNumber: 3, Key: "c", Value: "3", SortKey: "c"},
		}

		output2, _ := reducer2.Reduce(context.Background(), inputs2)

		if output1.StateHash != output2.StateHash {
			t.Errorf("Different input orders should produce same hash: %s != %s",
				output1.StateHash, output2.StateHash)
		}
	})

	t.Run("Empty inputs", func(t *testing.T) {
		reducer := NewDeterministicReducer(ConflictPolicyFirstSuccess)

		output, err := reducer.Reduce(context.Background(), nil)
		if err != nil {
			t.Fatalf("Reduce failed: %v", err)
		}

		if len(output.State) != 0 {
			t.Error("Empty inputs should produce empty state")
		}
	})
}

func TestReducerConfluenceVerification(t *testing.T) {
	t.Run("Basic confluence", func(t *testing.T) {
		reducer := NewDeterministicReducer(ConflictPolicyFirstSuccess)

		inputs := []ReducerInput{
			{SequenceNumber: 1, Key: "a", Value: "1", SortKey: "a"},
			{SequenceNumber: 2, Key: "b", Value: "2", SortKey: "b"},
			{SequenceNumber: 3, Key: "c", Value: "3", SortKey: "c"},
		}

		confluent, err := TestReducerConfluence(reducer, inputs, 5)
		if err != nil {
			t.Fatalf("Confluence test failed: %v", err)
		}
		if !confluent {
			t.Error("Reducer should be confluent")
		}
	})
}
