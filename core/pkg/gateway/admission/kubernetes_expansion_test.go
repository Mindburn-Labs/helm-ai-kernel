// Copyright The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0
//
// Test-only kubelet expansion oracle, copied from Kubernetes v1.35.3:
// https://github.com/kubernetes/kubernetes/blob/v1.35.3/third_party/forked/golang/expansion/expand.go
// Upstream SHA-256: bde54a536f9f39045d8a74a65e5a37d707b178b0557a87e01d3af97d907f8c24
// Changed the package to admission and prefixed identifiers to avoid test collisions.
// Expansion logic is unchanged.
// See the repository LICENSE for the Apache License, Version 2.0.

package admission

import (
	"bytes"
	"unicode/utf8"
)

const (
	kubeletExpansionOperator = '$'
	kubeletReferenceOpener   = '('
	kubeletReferenceCloser   = ')'
)

// kubeletSyntaxWrap returns the input string wrapped by the expansion syntax.
func kubeletSyntaxWrap(input string) string {
	return string(kubeletExpansionOperator) + string(kubeletReferenceOpener) + input + string(kubeletReferenceCloser)
}

// kubeletMappingFuncFor returns a mapping function for use with kubeletExpand that
// implements the expansion semantics defined in the expansion spec; it
// returns the input string wrapped in the expansion syntax if no mapping
// for the input is found.
func kubeletMappingFuncFor(context ...map[string]string) func(string) string {
	return func(input string) string {
		for _, vars := range context {
			val, ok := vars[input]
			if ok {
				return val
			}
		}

		return kubeletSyntaxWrap(input)
	}
}

// kubeletExpand replaces variable references in the input string according to
// the expansion spec using the given mapping function to resolve the
// values of variables.
func kubeletExpand(input string, mapping func(string) string) string {
	var buf bytes.Buffer
	checkpoint := 0
	for cursor := 0; cursor < len(input); cursor++ {
		if input[cursor] == kubeletExpansionOperator && cursor+1 < len(input) {
			// Copy the portion of the input string since the last
			// checkpoint into the buffer
			buf.WriteString(input[checkpoint:cursor])

			// Attempt to read the variable name as defined by the
			// syntax from the input string
			read, isVar, advance := kubeletTryReadVariableName(input[cursor+1:])

			if isVar {
				// We were able to read a variable name correctly;
				// apply the mapping to the variable name and copy the
				// bytes into the buffer
				buf.WriteString(mapping(read))
			} else {
				// Not a variable name; copy the read bytes into the buffer
				buf.WriteString(read)
			}

			// Advance the cursor in the input string to account for
			// bytes consumed to read the variable name expression
			cursor += advance

			// Advance the checkpoint in the input string
			checkpoint = cursor + 1
		}
	}

	// Return the buffer and any remaining unwritten bytes in the
	// input string.
	return buf.String() + input[checkpoint:]
}

// kubeletTryReadVariableName attempts to read a variable name from the input
// string and returns the content read from the input, whether that content
// represents a variable name to perform mapping on, and the number of bytes
// consumed in the input string.
//
// The input string is assumed not to contain the initial kubeletExpansionOperator.
func kubeletTryReadVariableName(input string) (string, bool, int) {
	r, size := utf8.DecodeRuneInString(input)
	switch r {
	case kubeletExpansionOperator:
		// Escaped kubeletExpansionOperator; return it.
		return input[0:size], false, size
	case kubeletReferenceOpener:
		// Scan to expression closer
		for i := 1; i < len(input); i++ {
			if input[i] == kubeletReferenceCloser {
				return input[1:i], true, i + 1
			}
		}

		// Incomplete reference; return it.
		return string(kubeletExpansionOperator) + string(kubeletReferenceOpener), false, 1
	default:
		// Not the beginning of an expression, ie, an kubeletExpansionOperator
		// that doesn't begin an expression.  Return the kubeletExpansionOperator
		// and the first rune in the string.

		return string(kubeletExpansionOperator) + string(r), false, size
	}
}
