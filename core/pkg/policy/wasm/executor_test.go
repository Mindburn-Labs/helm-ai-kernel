package wasm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildWasmModule constructs a minimal valid WASM binary that exports:
//   - A memory named "memory" with 1 page (64KB)
//   - A function named entrypoint with signature (i32, i32) -> i32
//     that returns the given constant value.
//
// The binary layout follows the WebAssembly 1.0 spec:
//
//	(module
//	  (type (func (param i32 i32) (result i32)))
//	  (func (type 0) i32.const <returnVal>)
//	  (memory 1)
//	  (export "memory" (memory 0))
//	  (export "<entrypoint>" (func 0))
//	)
func buildWasmModule(entrypoint string, returnVal int) []byte {
	// Helper to encode a WASM LEB128 unsigned integer (for small values <128).
	// For test modules with small names and body sizes this is sufficient.
	leb := func(v int) byte { return byte(v) }

	// --- Section payloads ---

	// Type section: one function type (i32, i32) -> i32
	typeSection := []byte{
		0x01,       // count: 1 type
		0x60,       // func type tag
		0x02,       // 2 params
		0x7f, 0x7f, // i32, i32
		0x01, // 1 result
		0x7f, // i32
	}

	// Function section: one function referencing type 0
	funcSection := []byte{
		0x01, // count: 1 function
		0x00, // type index 0
	}

	// Memory section: one memory with min=1 page, no max
	memorySection := []byte{
		0x01, // count: 1 memory
		0x00, // flags: no max
		0x01, // initial: 1 page (64KB)
	}

	// Export section: export "memory" (memory 0) and entrypoint (func 0)
	entrypointBytes := []byte(entrypoint)
	exportPayload := []byte{0x02} // count: 2 exports
	// Export 1: memory
	memName := []byte("memory")
	exportPayload = append(exportPayload, leb(len(memName)))
	exportPayload = append(exportPayload, memName...)
	exportPayload = append(exportPayload, 0x02) // export kind: memory
	exportPayload = append(exportPayload, 0x00) // memory index 0
	// Export 2: function
	exportPayload = append(exportPayload, leb(len(entrypointBytes)))
	exportPayload = append(exportPayload, entrypointBytes...)
	exportPayload = append(exportPayload, 0x00) // export kind: function
	exportPayload = append(exportPayload, 0x00) // func index 0

	// Code section: one function body
	// Function body: locals count + i32.const <val> + end
	var funcBody []byte
	funcBody = append(funcBody, 0x00) // local decl count: 0
	funcBody = append(funcBody, 0x41) // i32.const
	if returnVal >= 0 {
		funcBody = append(funcBody, leb(returnVal)) // value (LEB128)
	} else {
		// Encode a negative value as signed LEB128. For -1: 0x7f.
		funcBody = append(funcBody, byte(returnVal&0x7f))
	}
	funcBody = append(funcBody, 0x0b) // end

	codePayload := []byte{0x01}                       // count: 1 body
	codePayload = append(codePayload, leb(len(funcBody))) // body size
	codePayload = append(codePayload, funcBody...)

	// --- Assemble module ---
	var module []byte
	// Magic + version
	module = append(module, 0x00, 0x61, 0x73, 0x6d) // \0asm
	module = append(module, 0x01, 0x00, 0x00, 0x00) // version 1

	// Append each section: id, size (LEB128), payload
	appendSection := func(id byte, payload []byte) {
		module = append(module, id)
		module = append(module, leb(len(payload)))
		module = append(module, payload...)
	}

	appendSection(0x01, typeSection)   // Type
	appendSection(0x03, funcSection)   // Function
	appendSection(0x05, memorySection) // Memory
	appendSection(0x07, exportPayload) // Export
	appendSection(0x0a, codePayload)   // Code

	return module
}

// buildWasmModuleNoMemory constructs a WASM module that exports a function but
// no memory, useful for testing the "no memory" error path.
func buildWasmModuleNoMemory(entrypoint string) []byte {
	leb := func(v int) byte { return byte(v) }

	typeSection := []byte{
		0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
	}
	funcSection := []byte{0x01, 0x00}

	entrypointBytes := []byte(entrypoint)
	exportPayload := []byte{0x01} // 1 export
	exportPayload = append(exportPayload, leb(len(entrypointBytes)))
	exportPayload = append(exportPayload, entrypointBytes...)
	exportPayload = append(exportPayload, 0x00, 0x00)

	funcBody := []byte{0x00, 0x41, 0x01, 0x0b}
	codePayload := []byte{0x01, leb(len(funcBody))}
	codePayload = append(codePayload, funcBody...)

	var module []byte
	module = append(module, 0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00)

	appendSection := func(id byte, payload []byte) {
		module = append(module, id, leb(len(payload)))
		module = append(module, payload...)
	}
	appendSection(0x01, typeSection)
	appendSection(0x03, funcSection)
	appendSection(0x07, exportPayload)
	appendSection(0x0a, codePayload)

	return module
}

func hashOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestExecutor_BasicAllow(t *testing.T) {
	ctx := context.Background()
	exec, err := NewExecutor(ctx)
	require.NoError(t, err)
	defer exec.Close(ctx)

	wasmBytes := buildWasmModule("evaluate", 1)
	mod := &PolicyModule{
		Name:       "allow-all",
		Version:    "1.0.0",
		Binary:     wasmBytes,
		Hash:       hashOf(wasmBytes),
		Entrypoint: "evaluate",
	}

	result, err := exec.Execute(ctx, mod, map[string]interface{}{
		"principal": "agent-1",
		"action":    "read",
		"resource":  "data",
	})
	require.NoError(t, err)
	assert.Equal(t, "ALLOW", result.Decision)
	assert.Empty(t, result.Reason)
}

func TestExecutor_BasicDeny(t *testing.T) {
	ctx := context.Background()
	exec, err := NewExecutor(ctx)
	require.NoError(t, err)
	defer exec.Close(ctx)

	wasmBytes := buildWasmModule("evaluate", 0)
	mod := &PolicyModule{
		Name:       "deny-all",
		Version:    "1.0.0",
		Binary:     wasmBytes,
		Hash:       hashOf(wasmBytes),
		Entrypoint: "evaluate",
	}

	result, err := exec.Execute(ctx, mod, map[string]interface{}{
		"principal": "agent-1",
		"action":    "write",
		"resource":  "secrets",
	})
	require.NoError(t, err)
	assert.Equal(t, "DENY", result.Decision)
	assert.Contains(t, result.Reason, "deny")
}

func TestExecutor_InvalidModule(t *testing.T) {
	ctx := context.Background()
	exec, err := NewExecutor(ctx)
	require.NoError(t, err)
	defer exec.Close(ctx)

	garbage := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03}
	mod := &PolicyModule{
		Name:       "garbage",
		Version:    "0.0.1",
		Binary:     garbage,
		Hash:       hashOf(garbage),
		Entrypoint: "evaluate",
	}

	result, err := exec.Execute(ctx, mod, map[string]interface{}{"action": "test"})
	require.NoError(t, err)
	assert.Equal(t, "DENY", result.Decision, "invalid module must fail-closed to DENY")
	assert.Contains(t, result.Reason, "compilation failed")
}

func TestExecutor_MissingEntrypoint(t *testing.T) {
	ctx := context.Background()
	exec, err := NewExecutor(ctx)
	require.NoError(t, err)
	defer exec.Close(ctx)

	// Build a valid module that exports "evaluate", but ask for "nonexistent".
	wasmBytes := buildWasmModule("evaluate", 1)
	mod := &PolicyModule{
		Name:       "wrong-entry",
		Version:    "1.0.0",
		Binary:     wasmBytes,
		Hash:       hashOf(wasmBytes),
		Entrypoint: "nonexistent",
	}

	result, err := exec.Execute(ctx, mod, map[string]interface{}{"action": "test"})
	require.NoError(t, err)
	assert.Equal(t, "DENY", result.Decision)
	assert.Contains(t, result.Reason, "entrypoint")
	assert.Contains(t, result.Reason, "nonexistent")
}

func TestExecutor_NoMemory(t *testing.T) {
	ctx := context.Background()
	exec, err := NewExecutor(ctx)
	require.NoError(t, err)
	defer exec.Close(ctx)

	wasmBytes := buildWasmModuleNoMemory("evaluate")
	mod := &PolicyModule{
		Name:       "no-memory",
		Version:    "1.0.0",
		Binary:     wasmBytes,
		Hash:       hashOf(wasmBytes),
		Entrypoint: "evaluate",
	}

	result, err := exec.Execute(ctx, mod, map[string]interface{}{"action": "test"})
	require.NoError(t, err)
	assert.Equal(t, "DENY", result.Decision)
	assert.Contains(t, result.Reason, "memory", "should mention missing memory export")
}

func TestExecutor_ModuleCache(t *testing.T) {
	ctx := context.Background()
	exec, err := NewExecutor(ctx)
	require.NoError(t, err)
	defer exec.Close(ctx)

	wasmBytes := buildWasmModule("evaluate", 1)
	h := hashOf(wasmBytes)
	mod := &PolicyModule{
		Name:       "cached",
		Version:    "1.0.0",
		Binary:     wasmBytes,
		Hash:       h,
		Entrypoint: "evaluate",
	}

	// Execute twice — second call should hit the compiled module cache.
	result1, err := exec.Execute(ctx, mod, map[string]interface{}{"action": "read"})
	require.NoError(t, err)
	assert.Equal(t, "ALLOW", result1.Decision)

	result2, err := exec.Execute(ctx, mod, map[string]interface{}{"action": "write"})
	require.NoError(t, err)
	assert.Equal(t, "ALLOW", result2.Decision)

	// Verify cache has exactly one entry.
	exec.mu.RLock()
	cacheLen := len(exec.cache)
	_, cached := exec.cache[h]
	exec.mu.RUnlock()

	assert.Equal(t, 1, cacheLen, "only one compiled module should be cached")
	assert.True(t, cached, "module should be cached by its hash")
}

func TestExecutor_Isolation(t *testing.T) {
	// Verify that multiple evaluations of the same module do not share state.
	// Each evaluation gets a fresh module instance, so memory writes in one
	// should not affect another.
	ctx := context.Background()
	exec, err := NewExecutor(ctx)
	require.NoError(t, err)
	defer exec.Close(ctx)

	wasmBytes := buildWasmModule("evaluate", 1)
	mod := &PolicyModule{
		Name:       "isolated",
		Version:    "1.0.0",
		Binary:     wasmBytes,
		Hash:       hashOf(wasmBytes),
		Entrypoint: "evaluate",
	}

	// Run multiple evaluations concurrently.
	const concurrency = 10
	var wg sync.WaitGroup
	results := make([]*EvalResult, concurrency)
	errs := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = exec.Execute(ctx, mod, map[string]interface{}{
				"action": "read",
				"index":  idx,
			})
		}(i)
	}
	wg.Wait()

	for i := 0; i < concurrency; i++ {
		require.NoError(t, errs[i], "evaluation %d should not error", i)
		assert.Equal(t, "ALLOW", results[i].Decision, "evaluation %d should ALLOW", i)
	}
}

func TestExecutor_ContextCancellation(t *testing.T) {
	ctx := context.Background()
	exec, err := NewExecutor(ctx)
	require.NoError(t, err)
	defer exec.Close(ctx)

	wasmBytes := buildWasmModule("evaluate", 1)
	mod := &PolicyModule{
		Name:       "cancel-test",
		Version:    "1.0.0",
		Binary:     wasmBytes,
		Hash:       hashOf(wasmBytes),
		Entrypoint: "evaluate",
	}

	// Cancel context before execution.
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()

	result, err := exec.Execute(cancelCtx, mod, map[string]interface{}{"action": "read"})
	// With a cancelled context, we expect either an error or a DENY result.
	// The exact behavior depends on when wazero checks the context.
	if err != nil {
		return // acceptable: error on cancelled context
	}
	// If we got a result, it must be DENY (fail-closed).
	assert.Equal(t, "DENY", result.Decision)
}

func TestExecutor_NonBooleanReturn(t *testing.T) {
	// A module that returns 42 (not 0 or 1) should be treated as DENY.
	ctx := context.Background()
	exec, err := NewExecutor(ctx)
	require.NoError(t, err)
	defer exec.Close(ctx)

	wasmBytes := buildWasmModule("evaluate", 42)
	mod := &PolicyModule{
		Name:       "return-42",
		Version:    "1.0.0",
		Binary:     wasmBytes,
		Hash:       hashOf(wasmBytes),
		Entrypoint: "evaluate",
	}

	result, err := exec.Execute(ctx, mod, map[string]interface{}{"action": "test"})
	require.NoError(t, err)
	assert.Equal(t, "DENY", result.Decision, "non-1 return value must be DENY")
}
