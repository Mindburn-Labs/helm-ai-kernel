// quantum_posture: historical test fixtures retain classical receipt hashing;
// these helpers are test-only and grant no runtime spending authority.

package modelbound

// CheckBody parses body as one JSON object, refuses a key repeated at any
// depth, and checks it with Check. The Bound is never nil.
func CheckBody(api string, body []byte, opts Options) ([]Field, *Bound, *Refusal) {
	fields, err := ParseObject(body)
	if err != nil {
		return nil, &Bound{}, &Refusal{Code: "invalid_json", Message: err.Error()}
	}
	if err := CheckNoDuplicateKeys(body); err != nil {
		return fields, &Bound{}, &Refusal{Code: "invalid_json", Message: "the request body " + err.Error()}
	}
	bound, refusal := Check(api, fields, opts)
	return fields, bound, refusal
}
