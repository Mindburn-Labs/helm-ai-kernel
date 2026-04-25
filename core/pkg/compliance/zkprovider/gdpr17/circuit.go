package gdpr17

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

const (
	MaxEvents      = 16
	Scheme         = "groth16-bn254"
	CircuitVersion = "gdpr17-v1"
	CircuitID      = 17
	maxUnixSeconds = 253402300799
)

type Circuit struct {
	CircuitID     frontend.Variable `gnark:",public"`
	PolicyHash    frontend.Variable `gnark:",public"`
	ErasureUnix   frontend.Variable `gnark:",public"`
	SubjectCommit frontend.Variable `gnark:",public"`
	TraceCommit   frontend.Variable `gnark:",public"`

	SubjectScalar frontend.Variable
	SubjectNonce  frontend.Variable

	EventActive       [MaxEvents]frontend.Variable
	EventSubjectMatch [MaxEvents]frontend.Variable
	EventUnix         [MaxEvents]frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.CircuitID, CircuitID)
	api.AssertIsLessOrEqual(c.ErasureUnix, maxUnixSeconds)

	subjectHash, err := mimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("create subject commitment hash: %w", err)
	}
	subjectHash.Write(c.SubjectScalar, c.SubjectNonce)
	api.AssertIsEqual(subjectHash.Sum(), c.SubjectCommit)

	traceHash, err := mimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("create trace commitment hash: %w", err)
	}

	for i := 0; i < MaxEvents; i++ {
		active := c.EventActive[i]
		subjectMatch := c.EventSubjectMatch[i]
		eventUnix := c.EventUnix[i]

		api.AssertIsBoolean(active)
		api.AssertIsBoolean(subjectMatch)
		api.AssertIsLessOrEqual(eventUnix, maxUnixSeconds)

		inactive := api.Sub(1, active)
		api.AssertIsEqual(api.Mul(inactive, subjectMatch), 0)
		api.AssertIsEqual(api.Mul(inactive, eventUnix), 0)

		eventUnixIsZero := api.IsZero(eventUnix)
		api.AssertIsEqual(api.Mul(active, eventUnixIsZero), 0)

		isAfterErasure := api.IsZero(api.Sub(api.Cmp(eventUnix, c.ErasureUnix), 1))
		api.AssertIsEqual(api.Mul(active, subjectMatch, isAfterErasure), 0)

		traceHash.Write(active, subjectMatch, eventUnix)
	}

	api.AssertIsEqual(traceHash.Sum(), c.TraceCommit)
	return nil
}
