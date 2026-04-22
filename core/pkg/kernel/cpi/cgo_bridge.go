//go:build cpi_native

package cpi

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../../crates/helm-policy-vm/target/release -lhelm_policy_vm
#include "../../../../crates/helm-policy-vm/include/helm_cpi.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

// ErrInvalidInput is returned when the input bytes are malformed.
var ErrInvalidInput = errors.New("cpi: invalid input")

// ErrBundleMismatch is returned when bundle hashes don't match.
var ErrBundleMismatch = errors.New("cpi: bundle mismatch")

// ErrInternal is returned for VM internal errors.
var ErrInternal = errors.New("cpi: internal error")

func statusToError(s C.HelmStatus) error {
	switch s {
	case C.HELM_OK:
		return nil
	case C.HELM_ERR_INVALID_INPUT:
		return ErrInvalidInput
	case C.HELM_ERR_BUNDLE_MISMATCH:
		return ErrBundleMismatch
	default:
		return ErrInternal
	}
}

func bytesToHelm(b []byte) C.HelmBytes {
	if len(b) == 0 {
		return C.HelmBytes{data: nil, len: 0}
	}
	return C.HelmBytes{
		data: (*C.uint8_t)(unsafe.Pointer(&b[0])),
		len:  C.size_t(len(b)),
	}
}

func helmToBytes(h C.HelmBytes) []byte {
	if h.data == nil || h.len == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(h.data), C.int(h.len))
}

// Validate evaluates a PlanIRDelta against a snapshot using compiled policy bytecode.
//
// Returns the CpiVerdict as proto bytes.
func Validate(bytecode, snapshot, delta, facts []byte) ([]byte, error) {
	var verdictOut C.HelmBytes

	status := C.helm_cpi_validate(
		bytesToHelm(bytecode),
		bytesToHelm(snapshot),
		bytesToHelm(delta),
		bytesToHelm(facts),
		&verdictOut,
	)

	if err := statusToError(status); err != nil {
		return nil, err
	}

	result := helmToBytes(verdictOut)
	C.helm_free(verdictOut)
	return result, nil
}

// Explain generates a TooltipModelV1 from a CpiVerdict.
//
// Returns the TooltipModelV1 as proto bytes.
func Explain(verdict []byte) ([]byte, error) {
	var tooltipOut C.HelmBytes

	status := C.helm_cpi_explain(
		bytesToHelm(verdict),
		&tooltipOut,
	)

	if err := statusToError(status); err != nil {
		return nil, err
	}

	result := helmToBytes(tooltipOut)
	C.helm_free(tooltipOut)
	return result, nil
}

// Compile converts DSL source text to a PolicyBundle.
//
// Returns the PolicyBundle as proto bytes.
func Compile(source []byte) ([]byte, error) {
	var bundleOut C.HelmBytes

	status := C.helm_cpi_compile(
		bytesToHelm(source),
		&bundleOut,
	)

	if err := statusToError(status); err != nil {
		return nil, err
	}

	result := helmToBytes(bundleOut)
	C.helm_free(bundleOut)
	return result, nil
}
