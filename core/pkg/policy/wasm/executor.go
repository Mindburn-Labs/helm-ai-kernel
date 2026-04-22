// Executor runs compiled WASM policy modules using wazero with deterministic,
// sandboxed execution. Each evaluation instantiates a fresh module for isolation.
package wasm

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
)

// Executor runs compiled WASM policy modules with deterministic execution.
// It is safe for concurrent use; compiled modules are cached by content hash.
type Executor struct {
	runtime wazero.Runtime

	mu    sync.RWMutex
	cache map[string]wazero.CompiledModule // hash -> compiled
}

// NewExecutor creates a WASM executor with deterministic, context-cancellable config.
// The caller must call Close when the executor is no longer needed.
func NewExecutor(ctx context.Context) (*Executor, error) {
	cfg := wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true)

	rt := wazero.NewRuntimeWithConfig(ctx, cfg)

	return &Executor{
		runtime: rt,
		cache:   make(map[string]wazero.CompiledModule),
	}, nil
}

// Execute runs a WASM policy module with the given input and returns the
// evaluation result. The module must export:
//   - A memory named "memory"
//   - A function matching module.Entrypoint with signature (i32, i32) -> i32
//     that receives a pointer and length of JSON input in linear memory
//     and returns 0 for DENY, 1 for ALLOW.
//
// Fail-closed: any error during compilation, instantiation, or execution
// results in a DENY verdict.
func (e *Executor) Execute(ctx context.Context, module *PolicyModule, input map[string]interface{}) (*EvalResult, error) {
	// 1. Compile module if not cached.
	compiled, err := e.getOrCompile(ctx, module)
	if err != nil {
		return denyResult(fmt.Sprintf("compilation failed: %v", err)), nil
	}

	// 2. Instantiate a fresh, anonymous module per evaluation for isolation.
	// Empty name ("") allows multiple concurrent instantiations of the same
	// compiled module without name conflicts. We disable _start so the module
	// is not treated as a WASI command.
	mod, err := e.runtime.InstantiateModule(ctx, compiled,
		wazero.NewModuleConfig().
			WithName("").
			WithStartFunctions(), // no auto-start
	)
	if err != nil {
		return denyResult(fmt.Sprintf("instantiation failed: %v", err)), nil
	}
	defer func() { _ = mod.Close(ctx) }()

	// 3. Serialize input to JSON.
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return denyResult(fmt.Sprintf("input serialization failed: %v", err)), nil
	}

	// 4. Look up the entrypoint function.
	fn := mod.ExportedFunction(module.Entrypoint)
	if fn == nil {
		return denyResult(fmt.Sprintf("entrypoint %q not found", module.Entrypoint)), nil
	}

	// 5. Write input JSON to linear memory at offset 0.
	// The policy module contract requires a memory export named "memory".
	mem := mod.ExportedMemory("memory")
	if mem == nil {
		return denyResult("module has no exported memory named \"memory\""), nil
	}

	if uint32(len(inputBytes)) > mem.Size() {
		return denyResult(fmt.Sprintf("input size %d exceeds memory size %d", len(inputBytes), mem.Size())), nil
	}
	if !mem.Write(0, inputBytes) {
		return denyResult("failed to write input to memory"), nil
	}

	// 6. Call: entrypoint(input_ptr, input_len) -> result_code
	results, err := fn.Call(ctx, 0, uint64(len(inputBytes)))
	if err != nil {
		return denyResult(fmt.Sprintf("execution failed: %v", err)), nil
	}

	if len(results) == 0 {
		return denyResult("no return value from entrypoint"), nil
	}

	// 7. Interpret result: 1 = ALLOW, anything else = DENY.
	if results[0] == 1 {
		return &EvalResult{Decision: "ALLOW"}, nil
	}
	return &EvalResult{Decision: "DENY", Reason: "policy evaluation returned deny"}, nil
}

// getOrCompile returns a cached compiled module or compiles and caches it.
func (e *Executor) getOrCompile(ctx context.Context, module *PolicyModule) (wazero.CompiledModule, error) {
	e.mu.RLock()
	if cached, ok := e.cache[module.Hash]; ok {
		e.mu.RUnlock()
		return cached, nil
	}
	e.mu.RUnlock()

	// Double-checked locking: re-check under write lock.
	e.mu.Lock()
	defer e.mu.Unlock()
	if cached, ok := e.cache[module.Hash]; ok {
		return cached, nil
	}

	compiled, err := e.runtime.CompileModule(ctx, module.Binary)
	if err != nil {
		return nil, err
	}
	e.cache[module.Hash] = compiled
	return compiled, nil
}

// Close releases the wazero runtime and all cached compiled modules.
func (e *Executor) Close(ctx context.Context) error {
	return e.runtime.Close(ctx)
}

// denyResult is a convenience for fail-closed DENY results.
func denyResult(reason string) *EvalResult {
	return &EvalResult{Decision: "DENY", Reason: reason}
}
