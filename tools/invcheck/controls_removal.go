package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// proveRemoval applies one mutation and requires every test it names to fail.
// A mutation that does not compile, or an anchor that does not match exactly
// once, proves nothing. The tests passing without the mutation is checked by
// the run of all named tests.
func proveRemoval(root string, rp removalProof) problems {
	var p problems
	path := filepath.Join(root, filepath.FromSlash(rp.File))
	src, err := os.ReadFile(path)
	if err != nil {
		p.add("mutation-anchor", rp.Control, "cannot read %s: %v", rp.File, err)
		return p
	}
	if n := strings.Count(string(src), rp.Find); n != 1 {
		p.add("mutation-anchor", rp.Control, "removal proof find must match %s exactly once (matches %d)", rp.File, n)
		return p
	}

	tmp, err := os.MkdirTemp("", "invcheck-mutation-")
	if err != nil {
		p.add("mutation-run", rp.Control, "%v", err)
		return p
	}
	defer os.RemoveAll(tmp)
	mutated := filepath.Join(tmp, filepath.Base(path))
	overlay := filepath.Join(tmp, "overlay.json")
	absPath, _ := filepath.Abs(path)
	spec, _ := json.Marshal(map[string]map[string]string{"Replace": {absPath: mutated}})
	if err := os.WriteFile(mutated, []byte(strings.Replace(string(src), rp.Find, rp.Replace, 1)), 0o600); err != nil {
		p.add("mutation-run", rp.Control, "%v", err)
		return p
	}
	if err := os.WriteFile(overlay, spec, 0o600); err != nil {
		p.add("mutation-run", rp.Control, "%v", err)
		return p
	}

	var refs []ref
	for _, s := range rp.Tests {
		if r, ok := parseRef(s); ok {
			refs = append(refs, r)
		}
	}
	if len(refs) == 0 {
		return p
	}
	mod := module(refs[0].Dir)
	// A deleted control can turn a refusal into a call that blocks (a server
	// that now starts, say). The timeout bounds that; a killed run proves nothing.
	args := append([]string{"test", "-json", "-count=1", "-timeout", mutationTimeout, "-overlay", overlay, "-run", runPattern(refs)}, packageArgs(mod, refs)...)
	out, _ := goCmd(root, mod, testEnv(mod), args...)
	timedOut := strings.Contains(out, "panic: test timed out")
	events, err := testEvents(out)
	if err != nil {
		p.add("mutation-run", rp.Control, "%v", err)
		return p
	}
	got := outcomes(events)
	for _, s := range rp.Tests {
		if got[s] != "fail" {
			action := got[s]
			switch {
			case action == "" && timedOut:
				action = "no result: the run hit the " + mutationTimeout + " timeout, so the test blocks without the control"
			case action == "":
				action = "did not run (does the mutated package compile?)"
			}
			p.add("removal-not-proven", rp.Control, "%s with the control removed (%s): want fail, got %s", s, rp.File, action)
		}
	}
	return p
}

// proveAll runs the removal proofs a few at a time; each is an independent
// build of the mutated package and its tests.
func proveAll(root string, proofs []removalProof) (problems, int) {
	workers := runtime.NumCPU() / 2
	if workers < 2 {
		workers = 2
	}
	results := make([]problems, len(proofs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i, rp := range proofs {
		wg.Add(1)
		go func(i int, rp removalProof) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = proveRemoval(root, rp)
		}(i, rp)
	}
	wg.Wait()
	var all problems
	proven := 0
	for i, r := range results {
		if len(r) == 0 {
			proven++
			fmt.Printf("  removal proven: %s — %s fails without the control\n", proofs[i].Control, strings.Join(proofs[i].Tests, ", "))
		}
		all = append(all, r...)
	}
	return all, proven
}
