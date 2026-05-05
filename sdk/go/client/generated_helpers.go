package client

import (
	"bytes"
	"encoding/json"
)

type ReasonCode = string

const ReasonErrorInternal ReasonCode = "ERROR_INTERNAL"

type MappedNullable interface {
	ToMap() (map[string]interface{}, error)
}

func IsNil(i interface{}) bool {
	return i == nil
}

type NullableString struct {
	value *string
	isSet bool
}

func (v NullableString) Get() *string {
	return v.value
}

func (v *NullableString) Set(val *string) {
	v.value = val
	v.isSet = true
}

func (v NullableString) IsSet() bool {
	return v.isSet
}

func (v *NullableString) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableString(val *string) *NullableString {
	return &NullableString{value: val, isSet: true}
}

func (v NullableString) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableString) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

func newStrictDecoder(data []byte) *json.Decoder {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder
}
